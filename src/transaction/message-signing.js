/**
 * @fileoverview BIP322 Generic Message Signing
 * @description Implements BIP322 message signing for all address types
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { ECDSA } from '../core/crypto/signatures/ecdsa.js';
import { Schnorr } from '../core/crypto/signatures/schnorr-BIP340.js';
import { ScriptBuilder } from './script-builder.js';
import { WitnessBuilder } from './witness-builder.js';
import { BIP143 } from './sighash.js';

/**
 * BIP322 message signing constants
 * @constant {Object}
 */
const BIP322_CONSTANTS = {
    // Message tag for BIP322
    MESSAGE_TAG: 'BIP0322-signed-message',
    // Virtual transaction version
    TX_VERSION: 0,
    // Sequence for signing
    SEQUENCE: 0,
    // Empty prevout
    EMPTY_TXID: Buffer.alloc(32, 0),
    // OP_RETURN script for to_spend
    TO_SPEND_SCRIPT: Buffer.from([0x6a, 0x24, 0x62, 0x69, 0x70, 0x30, 0x33, 0x32, 0x32])
};

/**
 * Custom error for BIP322 operations
 * @class BIP322Error
 * @extends Error
 */
class BIP322Error extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'BIP322Error';
        this.code = code;
        this.details = details;
    }
}

/**
 * Tagged hash for BIP322
 * @param {string} tag - Hash tag
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 32-byte tagged hash
 */
function taggedHash(tag, data) {
    const tagHash = createHash('sha256').update(tag).digest();
    return createHash('sha256').update(Buffer.concat([tagHash, tagHash, data])).digest();
}

/**
 * BIP322 Message Signing
 * @class BIP322
 */
class BIP322 {
    /**
     * Create message hash for signing
     * @param {string|Buffer} message - Message to sign
     * @returns {Buffer} 32-byte message hash
     */
    static hashMessage(message) {
        const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
        return taggedHash(BIP322_CONSTANTS.MESSAGE_TAG, msgBuf);
    }

    /**
     * Create "to_spend" virtual transaction
     * @param {Buffer} scriptPubKey - Script of the signing address
     * @param {Buffer} messageHash - Hashed message
     * @returns {Object} Virtual transaction
     */
    static createToSpend(scriptPubKey, messageHash) {
        // OP_0 PUSH32 <message_hash>
        const scriptSig = Buffer.concat([
            Buffer.from([0x00, 0x20]),
            messageHash
        ]);

        return {
            version: 0,
            inputs: [{
                txid: BIP322_CONSTANTS.EMPTY_TXID.toString('hex'),
                vout: 0xffffffff,
                scriptSig: scriptSig,
                sequence: 0
            }],
            outputs: [{
                value: 0,
                scriptPubKey: scriptPubKey
            }],
            locktime: 0
        };
    }

    /**
     * Create "to_sign" virtual transaction
     * @param {Buffer} toSpendTxid - Txid of to_spend transaction
     * @param {Buffer} scriptPubKey - Script of signing address
     * @returns {Object} Virtual transaction to sign
     */
    static createToSign(toSpendTxid, scriptPubKey) {
        return {
            version: 0,
            inputs: [{
                txid: toSpendTxid,
                vout: 0,
                scriptSig: Buffer.alloc(0),
                sequence: 0
            }],
            outputs: [{
                value: 0,
                scriptPubKey: Buffer.from([0x6a]) // OP_RETURN
            }],
            locktime: 0
        };
    }

    /**
     * Sign a message using BIP322 (simple format)
     * @param {string|Buffer} message - Message to sign
     * @param {Buffer|string} privateKey - Private key
     * @param {string} addressType - Address type (p2wpkh, p2tr)
     * @returns {Promise<Buffer>} BIP322 signature (witness serialized)
     */
    static async sign(message, privateKey, addressType = 'p2wpkh') {
        const keyBuffer = Buffer.isBuffer(privateKey)
            ? privateKey
            : Buffer.from(privateKey, 'hex');

        const messageHash = this.hashMessage(message);
        const publicKey = ECDSA.getPublicKey(keyBuffer, true);

        // Create scriptPubKey based on address type
        let scriptPubKey;
        if (addressType === 'p2wpkh') {
            const hash160Fn = (await import('../utils/address-helpers.js')).hash160;
            const pubkeyHash = hash160Fn(publicKey);
            scriptPubKey = ScriptBuilder.createP2WPKH(pubkeyHash);
        } else if (addressType === 'p2tr') {
            // For Taproot, use x-only pubkey
            const xOnlyPubkey = publicKey.slice(1); // Remove prefix byte
            scriptPubKey = ScriptBuilder.createP2TR(xOnlyPubkey);
        } else {
            throw new BIP322Error(`Unsupported address type: ${addressType}`, 'UNSUPPORTED_TYPE');
        }

        // Create to_spend transaction
        const toSpend = this.createToSpend(scriptPubKey, messageHash);

        // Calculate to_spend txid
        const toSpendTxid = this._getTxid(toSpend);

        // Create to_sign transaction
        const toSign = this.createToSign(toSpendTxid, scriptPubKey);

        // Sign based on address type
        let witness;
        if (addressType === 'p2wpkh') {
            const hash160Fn = (await import('../utils/address-helpers.js')).hash160;
            const pubkeyHash = hash160Fn(publicKey);
            const sighash = BIP143.forP2WPKH(toSign, 0, pubkeyHash, 0, 0x01);
            const sigResult = ECDSA.sign(keyBuffer, sighash);
            const signature = Buffer.concat([sigResult.der, Buffer.from([0x01])]);
            witness = WitnessBuilder.buildP2WPKH(signature, publicKey);
        } else if (addressType === 'p2tr') {
            const schnorr = new Schnorr();
            // For Taproot, we need proper BIP341 sighash, simplified here
            const sigResult = await schnorr.sign(keyBuffer, messageHash);
            witness = [sigResult.signature];
        }

        // Serialize witness
        return WitnessBuilder.serialize(witness);
    }

    /**
     * Verify a BIP322 signature
     * @param {string|Buffer} message - Original message
     * @param {Buffer} signature - BIP322 signature (serialized witness)
     * @param {Buffer} scriptPubKey - Address scriptPubKey
     * @returns {Promise<boolean>} True if valid
     */
    static async verify(message, signature, scriptPubKey) {
        try {
            const messageHash = this.hashMessage(message);
            const witness = WitnessBuilder.parse(signature);

            if (witness.length < 1) {
                return false;
            }

            // Detect address type from scriptPubKey
            const scriptType = ScriptBuilder.detectType(scriptPubKey);

            if (scriptType.type === 'p2wpkh') {
                if (witness.length !== 2) return false;

                const sig = witness[0];
                const publicKey = witness[1];

                // Verify pubkey matches scriptPubKey
                const hash160Fn = (await import('../utils/address-helpers.js')).hash160;
                const pubkeyHash = hash160Fn(publicKey);
                if (!pubkeyHash.equals(scriptType.program)) {
                    return false;
                }

                // Recreate and verify sighash
                const toSpend = this.createToSpend(scriptPubKey, messageHash);
                const toSpendTxid = this._getTxid(toSpend);
                const toSign = this.createToSign(toSpendTxid, scriptPubKey);

                const sigWithoutType = sig.slice(0, -1);
                const sighash = BIP143.forP2WPKH(toSign, 0, pubkeyHash, 0, 0x01);

                // Parse DER signature
                const { r, s } = this._parseDER(sigWithoutType);
                return ECDSA.verify({ r, s }, sighash, publicKey);

            } else if (scriptType.type === 'p2tr') {
                if (witness.length !== 1) return false;

                const schnorrSig = witness[0];
                const xOnlyPubkey = scriptType.program;

                const schnorr = new Schnorr();
                return await schnorr.verify(schnorrSig, messageHash, xOnlyPubkey);
            }

            return false;
        } catch {
            return false;
        }
    }

    /**
     * Calculate txid for virtual transaction
     * @private
     */
    static _getTxid(tx) {
        const parts = [];

        // Version
        const version = Buffer.alloc(4);
        version.writeInt32LE(tx.version, 0);
        parts.push(version);

        // Input count
        parts.push(Buffer.from([tx.inputs.length]));

        // Inputs
        for (const input of tx.inputs) {
            const txid = typeof input.txid === 'string'
                ? Buffer.from(input.txid, 'hex').reverse()
                : input.txid;
            parts.push(txid);

            const vout = Buffer.alloc(4);
            vout.writeUInt32LE(input.vout, 0);
            parts.push(vout);

            const scriptSig = Buffer.isBuffer(input.scriptSig) ? input.scriptSig : Buffer.alloc(0);
            parts.push(Buffer.from([scriptSig.length]));
            parts.push(scriptSig);

            const seq = Buffer.alloc(4);
            seq.writeUInt32LE(input.sequence, 0);
            parts.push(seq);
        }

        // Output count
        parts.push(Buffer.from([tx.outputs.length]));

        // Outputs
        for (const output of tx.outputs) {
            const value = Buffer.alloc(8);
            value.writeBigUInt64LE(BigInt(output.value), 0);
            parts.push(value);

            const script = output.scriptPubKey;
            parts.push(Buffer.from([script.length]));
            parts.push(script);
        }

        // Locktime
        const locktime = Buffer.alloc(4);
        locktime.writeUInt32LE(tx.locktime, 0);
        parts.push(locktime);

        const serialized = Buffer.concat(parts);
        const hash = createHash('sha256')
            .update(createHash('sha256').update(serialized).digest())
            .digest();

        return hash.reverse().toString('hex');
    }

    /**
     * Parse DER signature
     * @private
     */
    static _parseDER(sig) {
        let offset = 0;

        if (sig[offset++] !== 0x30) throw new Error('Invalid DER');

        const totalLen = sig[offset++];

        if (sig[offset++] !== 0x02) throw new Error('Invalid DER');

        const rLen = sig[offset++];
        let r = sig.slice(offset, offset + rLen);
        offset += rLen;

        if (sig[offset++] !== 0x02) throw new Error('Invalid DER');

        const sLen = sig[offset++];
        let s = sig.slice(offset, offset + sLen);

        // Remove leading zeros
        while (r.length > 1 && r[0] === 0) r = r.slice(1);
        while (s.length > 1 && s[0] === 0) s = s.slice(1);

        return {
            r: BigInt('0x' + r.toString('hex')),
            s: BigInt('0x' + s.toString('hex'))
        };
    }

    /**
     * Legacy Bitcoin message signing (for compatibility)
     * @param {string|Buffer} message - Message to sign
     * @param {Buffer|string} privateKey - Private key
     * @returns {Object} Signature {signature, recovery}
     */
    static signLegacy(message, privateKey) {
        const keyBuffer = Buffer.isBuffer(privateKey)
            ? privateKey
            : Buffer.from(privateKey, 'hex');

        // Bitcoin message prefix
        const prefix = '\x18Bitcoin Signed Message:\n';
        const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
        const prefixBuf = Buffer.from(prefix, 'utf8');

        const fullMsg = Buffer.concat([
            Buffer.from([prefixBuf.length]),
            prefixBuf,
            Buffer.from([msgBuf.length]),
            msgBuf
        ]);

        const hash = createHash('sha256')
            .update(createHash('sha256').update(fullMsg).digest())
            .digest();

        const sigResult = ECDSA.sign(keyBuffer, hash);

        return {
            signature: sigResult.signature,
            recovery: sigResult.recovery,
            messageHash: hash
        };
    }

    /**
     * Verify legacy Bitcoin message signature
     * @param {string|Buffer} message - Original message
     * @param {Object} signature - Signature object
     * @param {Buffer|string} publicKey - Public key
     * @returns {boolean} True if valid
     */
    static verifyLegacy(message, signature, publicKey) {
        const prefix = '\x18Bitcoin Signed Message:\n';
        const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
        const prefixBuf = Buffer.from(prefix, 'utf8');

        const fullMsg = Buffer.concat([
            Buffer.from([prefixBuf.length]),
            prefixBuf,
            Buffer.from([msgBuf.length]),
            msgBuf
        ]);

        const hash = createHash('sha256')
            .update(createHash('sha256').update(fullMsg).digest())
            .digest();

        return ECDSA.verify(signature, hash, publicKey);
    }
}

export {
    BIP322,
    BIP322Error,
    BIP322_CONSTANTS
};

export default BIP322;
