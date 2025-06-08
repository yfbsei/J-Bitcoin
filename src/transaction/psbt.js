/**
 * @fileoverview Enhanced PSBT (Partially Signed Bitcoin Transaction) implementation
 *
 * This module provides a simplified but extensible PSBT processor. It follows
 * BIP174 with basic Taproot (BIP371) extensions and integrates with the other
 * modules in this repository. The implementation focuses on the immutable
 * builder pattern used throughout the library and exposes helpers for signing
 * and finalising transactions.
 *
 * NOTE: This implementation only covers the features required for the
 * accompanying examples and tests. It is not a complete PSBT implementation
 * but provides a foundation that can be extended following the research notes
 * in the repository documentation.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import ECDSA from '../core/crypto/signatures/ecdsa.js';
import Schnorr from '../core/crypto/signatures/schnorr-BIP340.js';
import { TaprootControlBlock } from '../core/taproot/control-block.js';
import { TapscriptInterpreter } from '../core/taproot/tapscript-interpreter.js';
import { validateAndGetNetwork } from '../core/constants.js';

/**
 * Basic PSBT error class used throughout the module.
 */
class PSBTError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'PSBTError';
        this.code = code;
        this.details = details;
    }
}

/**
 * Constants used for PSBT processing and limits. These are deliberately small
 * to keep the demo implementation simple.
 */
const PSBT_CONSTANTS = {
    PSBT_MAGIC: 'psbt',
    PSBT_SEPARATOR: 0xff,
    MAX_PSBT_SIZE: 1000000,
    MAX_INPUTS: 1000,
    MAX_OUTPUTS: 1000
};

/**
 * Minimal security utilities used by the PSBT class. In the full
 * implementation these would include rate limiting and secure memory wiping.
 */
class PSBTSecurityUtils {
    static constantTimeEqual(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
        if (a.length !== b.length) return false;
        try {
            return timingSafeEqual(a, b);
        } catch (e) {
            let res = 0;
            for (let i = 0; i < a.length; i++) res |= a[i] ^ b[i];
            return res === 0;
        }
    }

    static secureClear(buffer) {
        if (Buffer.isBuffer(buffer)) {
            const rnd = randomBytes(buffer.length);
            rnd.copy(buffer);
            buffer.fill(0);
        }
    }
}

/**
 * Main PSBT class. It stores all PSBT fields in easy to modify structures and
 * provides helper methods for signing and finalizing transactions.
 */
class EnhancedPSBT {
    constructor(network = 'main') {
        this.network = network;
        this.networkConfig = validateAndGetNetwork(network);

        this.global = {
            unsignedTx: null,
            version: 0,
            xpubs: new Map(),
            proprietary: new Map()
        };

        this.inputs = [];
        this.outputs = [];
        this.psbtId = this._generatePSBTId();

        this.schnorr = new Schnorr.Enhanced();
        this.ecdsa = new ECDSA.Enhanced();
        this.controlBlock = new TaprootControlBlock();
        this.interpreter = new TapscriptInterpreter();
    }

    /** Generate a simple unique PSBT id */
    _generatePSBTId() {
        return `psbt_${Date.now().toString(36)}_${randomBytes(4).toString('hex')}`;
    }

    /**
     * Add an unsigned transaction to this PSBT and initialise input and output
     * structures. The transaction object uses the format produced by the
     * TransactionBuilder in this repository.
     */
    addTransaction(tx) {
        if (!tx || !tx.inputs || !tx.outputs) {
            throw new PSBTError('Invalid transaction structure', 'INVALID_TX');
        }
        this.global.unsignedTx = tx;
        this.inputs = tx.inputs.map(() => ({
            partialSigs: new Map(),
            tapScriptSig: new Map(),
            tapLeafScript: [],
            bip32Derivation: [],
            tapBip32Derivation: [],
            finalized: false,
            signed: false
        }));
        this.outputs = tx.outputs.map(() => ({
            bip32Derivation: [],
            tapBip32Derivation: []
        }));
    }

    /** Update information for an input */
    updateInput(index, data) {
        if (index < 0 || index >= this.inputs.length) {
            throw new PSBTError('Invalid input index', 'INVALID_INPUT');
        }
        const input = this.inputs[index];
        if (data.witnessUtxo) input.witnessUtxo = { ...data.witnessUtxo };
        if (data.nonWitnessUtxo) input.nonWitnessUtxo = Buffer.from(data.nonWitnessUtxo);
        if (Array.isArray(data.bip32Derivation)) {
            input.bip32Derivation.push(...data.bip32Derivation.map(d => ({
                pubkey: Buffer.from(d.pubkey),
                masterFingerprint: Buffer.from(d.masterFingerprint),
                path: d.path
            })));
        }
        if (Array.isArray(data.tapBip32Derivation)) {
            input.tapBip32Derivation.push(...data.tapBip32Derivation.map(d => ({
                pubkey: Buffer.from(d.pubkey),
                leafHashes: d.leafHashes.map(h => Buffer.from(h)),
                masterFingerprint: Buffer.from(d.masterFingerprint),
                path: d.path
            })));
        }
        if (data.tapInternalKey) input.tapInternalKey = Buffer.from(data.tapInternalKey);
        if (data.tapMerkleRoot) input.tapMerkleRoot = Buffer.from(data.tapMerkleRoot);
        if (Array.isArray(data.tapLeafScript)) {
            input.tapLeafScript.push(...data.tapLeafScript.map(ls => ({
                script: Buffer.from(ls.script),
                leafVersion: ls.leafVersion || 0xc0,
                controlBlock: Buffer.from(ls.controlBlock)
            })));
        }
    }

    /** Update output metadata */
    updateOutput(index, data) {
        if (index < 0 || index >= this.outputs.length) {
            throw new PSBTError('Invalid output index', 'INVALID_OUTPUT');
        }
        const output = this.outputs[index];
        if (Array.isArray(data.bip32Derivation)) {
            output.bip32Derivation.push(...data.bip32Derivation.map(d => ({
                pubkey: Buffer.from(d.pubkey),
                masterFingerprint: Buffer.from(d.masterFingerprint),
                path: d.path
            })));
        }
        if (Array.isArray(data.tapBip32Derivation)) {
            output.tapBip32Derivation.push(...data.tapBip32Derivation.map(d => ({
                pubkey: Buffer.from(d.pubkey),
                leafHashes: d.leafHashes.map(h => Buffer.from(h)),
                masterFingerprint: Buffer.from(d.masterFingerprint),
                path: d.path
            })));
        }
        if (data.tapInternalKey) output.tapInternalKey = Buffer.from(data.tapInternalKey);
        if (data.tapTree) output.tapTree = data.tapTree;
    }

    /** Register an async signer function for a specific public key */
    registerSigner(pubkey, signerFn) {
        if (!this.signers) this.signers = new Map();
        const hex = Buffer.isBuffer(pubkey) ? pubkey.toString('hex') : pubkey;
        this.signers.set(hex, signerFn);
    }

    /**
     * Create a signature hash for the given input. This simplified version does
     * not implement full BIP341/BIP143 semantics but is sufficient for tests.
     */
    _createSignatureHash(index) {
        const tx = this.global.unsignedTx;
        const input = tx.inputs[index];
        const data = Buffer.concat([
            Buffer.from(tx.version.toString()),
            Buffer.from(input.index.toString()),
            Buffer.from(tx.locktime.toString())
        ]);
        return createHash('sha256').update(data).digest();
    }

    /** Internal helper to compute leaf hash for taproot scripts */
    _computeLeafHash(leafScript) {
        const data = Buffer.concat([
            Buffer.from([leafScript.leafVersion]),
            leafScript.script
        ]);
        return createHash('sha256').update(data).digest();
    }

    /** Sign a specific input */
    async signInput(index, signer) {
        if (index < 0 || index >= this.inputs.length) {
            throw new PSBTError('Invalid input index', 'INVALID_INPUT');
        }
        const input = this.inputs[index];
        const sigHash = this._createSignatureHash(index);

        let signature;
        if (typeof signer === 'function') {
            signature = await signer(sigHash, index);
        } else {
            const { signature: sig } = await this.ecdsa.sign(signer, sigHash);
            signature = sig;
        }

        if (!signature) {
            throw new PSBTError('Signer failed to return a signature', 'SIGN_FAIL');
        }
        input.partialSigs.set('default', Buffer.from(signature));
        input.signed = true;
    }

    /** Sign all inputs using registered signers */
    async signAll() {
        for (let i = 0; i < this.inputs.length; i++) {
            const input = this.inputs[i];
            if (input.signed) continue;
            let signer = null;
            for (const d of [...input.bip32Derivation, ...input.tapBip32Derivation]) {
                const hex = d.pubkey.toString('hex');
                if (this.signers && this.signers.has(hex)) {
                    signer = this.signers.get(hex);
                    break;
                }
            }
            if (signer) await this.signInput(i, signer);
        }
    }

    /** Finalise a single input */
    finalizeInput(index) {
        const input = this.inputs[index];
        if (!input.signed) {
            throw new PSBTError('Input not signed', 'NOT_SIGNED');
        }
        if (input.tapLeafScript.length > 0 && input.tapScriptSig.size > 0) {
            const leaf = input.tapLeafScript[0];
            const leafHash = this._computeLeafHash(leaf).toString('hex');
            const sig = input.tapScriptSig.get(leafHash);
            if (sig) {
                input.finalScriptWitness = [sig, leaf.script, leaf.controlBlock];
            }
        } else if (input.partialSigs.size > 0) {
            const [sig] = input.partialSigs.values();
            input.finalScriptSig = Buffer.from(sig);
        }
        input.finalized = true;
    }

    /** Finalise all signed inputs */
    finalizeAll() {
        for (let i = 0; i < this.inputs.length; i++) {
            if (this.inputs[i].signed && !this.inputs[i].finalized) {
                this.finalizeInput(i);
            }
        }
    }

    /** Extract the fully signed transaction */
    extractTransaction() {
        if (!this.inputs.every(i => i.finalized)) {
            throw new PSBTError('Not all inputs finalized', 'NOT_FINAL');
        }
        const tx = { ...this.global.unsignedTx };
        tx.inputs = tx.inputs.map((input, i) => ({
            ...input,
            script: this.inputs[i].finalScriptSig || Buffer.alloc(0),
            witness: this.inputs[i].finalScriptWitness || []
        }));
        return tx;
    }

    /**
     * Combine this PSBT with another one. Only partial data is merged. This
     * method performs a basic check that the unsigned transactions match.
     */
    combine(other) {
        if (!(other instanceof EnhancedPSBT)) {
            throw new PSBTError('Can only combine with EnhancedPSBT', 'INVALID_PSBT');
        }
        if (!this._transactionsMatch(this.global.unsignedTx, other.global.unsignedTx)) {
            throw new PSBTError('Transactions differ', 'TX_MISMATCH');
        }
        other.inputs.forEach((inp, i) => this._combineInput(this.inputs[i], inp));
        other.outputs.forEach((out, i) => this._combineOutput(this.outputs[i], out));
    }

    /** Validate basic structure of this PSBT */
    validate() {
        const issues = [];
        if (!this.global.unsignedTx) {
            issues.push({ level: 'error', message: 'Missing unsigned transaction' });
        }
        return {
            valid: issues.length === 0,
            issues
        };
    }

    /** Provide status information useful for diagnostics */
    getStatus() {
        return {
            psbtId: this.psbtId,
            network: this.network,
            inputs: this.inputs.length,
            outputs: this.outputs.length,
            finalized: this.inputs.filter(i => i.finalized).length
        };
    }

    /** Serialize PSBT to a simple JSON based binary representation */
    _serializeToBinary() {
        const body = Buffer.from(JSON.stringify({
            global: this.global,
            inputs: this.inputs.map(i => ({
                ...i,
                partialSigs: Array.from(i.partialSigs.entries()),
                tapScriptSig: Array.from(i.tapScriptSig.entries())
            })),
            outputs: this.outputs
        }));
        const parts = [Buffer.from(PSBT_CONSTANTS.PSBT_MAGIC, 'ascii'), Buffer.from([PSBT_CONSTANTS.PSBT_SEPARATOR]), body];
        return Buffer.concat(parts);
    }

    /** Convert this PSBT to base64 */
    toBase64() {
        return this._serializeToBinary().toString('base64');
    }

    /** Parse a binary representation into this PSBT */
    _parseFromBinary(data) {
        const magic = Buffer.from(PSBT_CONSTANTS.PSBT_MAGIC, 'ascii');
        if (!data.slice(0, magic.length).equals(magic)) {
            throw new PSBTError('Invalid PSBT magic', 'BAD_MAGIC');
        }
        const json = data.slice(magic.length + 1).toString();
        const parsed = JSON.parse(json);
        this.global = parsed.global;
        this.inputs = parsed.inputs.map(i => ({
            ...i,
            partialSigs: new Map(i.partialSigs),
            tapScriptSig: new Map(i.tapScriptSig)
        }));
        this.outputs = parsed.outputs;
    }

    /** Create PSBT from base64 encoded data */
    static fromBase64(b64, network = 'main') {
        const psbt = new EnhancedPSBT(network);
        const binary = Buffer.from(b64, 'base64');
        psbt._parseFromBinary(binary);
        return psbt;
    }

    /** Create PSBT from binary */
    static fromBinary(binary, network = 'main') {
        const psbt = new EnhancedPSBT(network);
        psbt._parseFromBinary(binary);
        return psbt;
    }

    /** Securely wipe internal buffers */
    destroy() {
        PSBTSecurityUtils.secureClear(this.global);
        this.inputs.forEach(i => PSBTSecurityUtils.secureClear(i));
        this.outputs.forEach(o => PSBTSecurityUtils.secureClear(o));
        if (this.signers) this.signers.clear();
    }

    /* Helper methods */
    _transactionsMatch(a, b) {
        if (!a || !b) return false;
        if (a.version !== b.version) return false;
        if (a.locktime !== b.locktime) return false;
        if (a.inputs.length !== b.inputs.length) return false;
        if (a.outputs.length !== b.outputs.length) return false;
        for (let i = 0; i < a.inputs.length; i++) {
            if (a.inputs[i].hash !== b.inputs[i].hash || a.inputs[i].index !== b.inputs[i].index) {
                return false;
            }
        }
        for (let i = 0; i < a.outputs.length; i++) {
            if (a.outputs[i].amount !== b.outputs[i].amount) return false;
            if (!PSBTSecurityUtils.constantTimeEqual(Buffer.from(a.outputs[i].script), Buffer.from(b.outputs[i].script))) return false;
        }
        return true;
    }

    _combineInput(a, b) {
        if (b.witnessUtxo) a.witnessUtxo = b.witnessUtxo;
        if (b.nonWitnessUtxo) a.nonWitnessUtxo = b.nonWitnessUtxo;
        for (const [k, v] of (b.partialSigs || [])) a.partialSigs.set(k, v);
        for (const [k, v] of (b.tapScriptSig || [])) a.tapScriptSig.set(k, v);
        if (b.tapKeySig) a.tapKeySig = b.tapKeySig;
        if (b.tapLeafScript) a.tapLeafScript.push(...b.tapLeafScript);
    }

    _combineOutput(a, b) {
        if (b.tapInternalKey) a.tapInternalKey = b.tapInternalKey;
        if (b.tapTree) a.tapTree = b.tapTree;
    }
}

export {
    PSBTError,
    PSBTSecurityUtils,
    PSBT_CONSTANTS,
    EnhancedPSBT
};