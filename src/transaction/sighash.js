/**
 * @fileoverview Sighash calculation for Bitcoin transactions
 * @description Implements BIP143 (SegWit) and BIP341 (Taproot) sighash algorithms
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';

/**
 * Sighash types
 * @constant {Object}
 */
const SIGHASH = {
    ALL: 0x01,
    NONE: 0x02,
    SINGLE: 0x03,
    ANYONECANPAY: 0x80,
    DEFAULT: 0x00, // Taproot only
    ALL_ANYONECANPAY: 0x81,
    NONE_ANYONECANPAY: 0x82,
    SINGLE_ANYONECANPAY: 0x83
};

/**
 * Custom error class for sighash operations
 * @class SighashError
 * @extends Error
 */
class SighashError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'SighashError';
        this.code = code;
        this.details = details;
    }
}

/**
 * SHA256 hash helper
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 32-byte hash
 */
function sha256(data) {
    return createHash('sha256').update(data).digest();
}

/**
 * Double SHA256 hash
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 32-byte hash
 */
function hash256(data) {
    return sha256(sha256(data));
}

/**
 * Tagged hash for Taproot (BIP340)
 * @param {string} tag - Hash tag
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 32-byte tagged hash
 */
function taggedHash(tag, data) {
    const tagHash = sha256(Buffer.from(tag, 'utf8'));
    return sha256(Buffer.concat([tagHash, tagHash, data]));
}

/**
 * Encode a variable-length integer
 * @param {number|bigint} n - Number to encode
 * @returns {Buffer} VarInt encoded
 */
function encodeVarInt(n) {
    const num = typeof n === 'bigint' ? Number(n) : n;
    if (num < 0xfd) {
        return Buffer.from([num]);
    } else if (num <= 0xffff) {
        const buf = Buffer.alloc(3);
        buf[0] = 0xfd;
        buf.writeUInt16LE(num, 1);
        return buf;
    } else if (num <= 0xffffffff) {
        const buf = Buffer.alloc(5);
        buf[0] = 0xfe;
        buf.writeUInt32LE(num, 1);
        return buf;
    } else {
        const buf = Buffer.alloc(9);
        buf[0] = 0xff;
        buf.writeBigUInt64LE(BigInt(num), 1);
        return buf;
    }
}

/**
 * Create scriptCode for P2WPKH sighash
 * @param {Buffer} pubkeyHash - 20-byte public key hash
 * @returns {Buffer} scriptCode
 */
function createP2WPKHScriptCode(pubkeyHash) {
    if (pubkeyHash.length !== 20) {
        throw new SighashError('Invalid pubkey hash length', 'INVALID_PUBKEY_HASH');
    }
    // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    return Buffer.concat([
        Buffer.from([0x19, 0x76, 0xa9, 0x14]),
        pubkeyHash,
        Buffer.from([0x88, 0xac])
    ]);
}

/**
 * BIP143 - SegWit Sighash Calculator
 * @class BIP143
 */
class BIP143 {
    /**
     * Calculate hashPrevouts
     * @param {Array} inputs - Transaction inputs
     * @param {number} sighashType - Sighash type
     * @returns {Buffer} 32-byte hash
     */
    static hashPrevouts(inputs, sighashType) {
        if (sighashType & SIGHASH.ANYONECANPAY) {
            return Buffer.alloc(32, 0);
        }

        const data = [];
        for (const input of inputs) {
            const txid = typeof input.txid === 'string'
                ? Buffer.from(input.txid, 'hex').reverse()
                : Buffer.from(input.txid).reverse();
            const vout = Buffer.alloc(4);
            vout.writeUInt32LE(input.vout, 0);
            data.push(txid, vout);
        }

        return hash256(Buffer.concat(data));
    }

    /**
     * Calculate hashSequence
     * @param {Array} inputs - Transaction inputs
     * @param {number} sighashType - Sighash type
     * @returns {Buffer} 32-byte hash
     */
    static hashSequence(inputs, sighashType) {
        const baseType = sighashType & 0x1f;
        if ((sighashType & SIGHASH.ANYONECANPAY) ||
            baseType === SIGHASH.SINGLE ||
            baseType === SIGHASH.NONE) {
            return Buffer.alloc(32, 0);
        }

        const data = [];
        for (const input of inputs) {
            const seq = Buffer.alloc(4);
            seq.writeUInt32LE(input.sequence ?? 0xffffffff, 0);
            data.push(seq);
        }

        return hash256(Buffer.concat(data));
    }

    /**
     * Calculate hashOutputs
     * @param {Array} outputs - Transaction outputs
     * @param {number} inputIndex - Current input index
     * @param {number} sighashType - Sighash type
     * @returns {Buffer} 32-byte hash
     */
    static hashOutputs(outputs, inputIndex, sighashType) {
        const baseType = sighashType & 0x1f;

        if (baseType === SIGHASH.NONE) {
            return Buffer.alloc(32, 0);
        }

        if (baseType === SIGHASH.SINGLE) {
            if (inputIndex >= outputs.length) {
                return Buffer.alloc(32, 0);
            }
            const output = outputs[inputIndex];
            return hash256(this._serializeOutput(output));
        }

        // SIGHASH_ALL
        const data = outputs.map(o => this._serializeOutput(o));
        return hash256(Buffer.concat(data));
    }

    /**
     * Serialize a single output
     * @private
     */
    static _serializeOutput(output) {
        const value = Buffer.alloc(8);
        value.writeBigUInt64LE(BigInt(output.value), 0);

        const script = Buffer.isBuffer(output.scriptPubKey)
            ? output.scriptPubKey
            : Buffer.from(output.scriptPubKey, 'hex');

        return Buffer.concat([value, encodeVarInt(script.length), script]);
    }

    /**
     * Calculate BIP143 sighash for SegWit inputs
     * @param {Object} tx - Transaction object
     * @param {number} inputIndex - Input being signed
     * @param {Buffer} scriptCode - Script code for input
     * @param {number} value - Input value in satoshis
     * @param {number} [sighashType=0x01] - Sighash type
     * @returns {Buffer} 32-byte sighash
     */
    static calculate(tx, inputIndex, scriptCode, value, sighashType = SIGHASH.ALL) {
        if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
            throw new SighashError('Invalid input index', 'INVALID_INDEX');
        }

        const input = tx.inputs[inputIndex];

        // 1. nVersion (4 bytes)
        const version = Buffer.alloc(4);
        version.writeInt32LE(tx.version ?? 2, 0);

        // 2. hashPrevouts (32 bytes)
        const prevouts = this.hashPrevouts(tx.inputs, sighashType);

        // 3. hashSequence (32 bytes)
        const sequence = this.hashSequence(tx.inputs, sighashType);

        // 4. outpoint (36 bytes)
        const txid = typeof input.txid === 'string'
            ? Buffer.from(input.txid, 'hex').reverse()
            : Buffer.from(input.txid).reverse();
        const vout = Buffer.alloc(4);
        vout.writeUInt32LE(input.vout, 0);
        const outpoint = Buffer.concat([txid, vout]);

        // 5. scriptCode (with length prefix already included)
        const scriptCodeData = Buffer.isBuffer(scriptCode) ? scriptCode : Buffer.from(scriptCode, 'hex');

        // 6. value (8 bytes)
        const valueBuf = Buffer.alloc(8);
        valueBuf.writeBigUInt64LE(BigInt(value), 0);

        // 7. nSequence (4 bytes)
        const nSequence = Buffer.alloc(4);
        nSequence.writeUInt32LE(input.sequence ?? 0xffffffff, 0);

        // 8. hashOutputs (32 bytes)
        const outputs = this.hashOutputs(tx.outputs, inputIndex, sighashType);

        // 9. nLocktime (4 bytes)
        const locktime = Buffer.alloc(4);
        locktime.writeUInt32LE(tx.locktime ?? 0, 0);

        // 10. sighash type (4 bytes)
        const sigType = Buffer.alloc(4);
        sigType.writeUInt32LE(sighashType, 0);

        // Concatenate all and double SHA256
        const preimage = Buffer.concat([
            version,
            prevouts,
            sequence,
            outpoint,
            scriptCodeData,
            valueBuf,
            nSequence,
            outputs,
            locktime,
            sigType
        ]);

        return hash256(preimage);
    }

    /**
     * Calculate sighash for P2WPKH input
     * @param {Object} tx - Transaction object
     * @param {number} inputIndex - Input index
     * @param {Buffer} pubkeyHash - 20-byte public key hash
     * @param {number} value - Input value in satoshis
     * @param {number} [sighashType=0x01] - Sighash type
     * @returns {Buffer} 32-byte sighash
     */
    static forP2WPKH(tx, inputIndex, pubkeyHash, value, sighashType = SIGHASH.ALL) {
        const scriptCode = createP2WPKHScriptCode(pubkeyHash);
        return this.calculate(tx, inputIndex, scriptCode, value, sighashType);
    }
}

/**
 * BIP341 - Taproot Sighash Calculator
 * @class BIP341
 */
class BIP341 {
    /**
     * Calculate sha_prevouts for Taproot
     * @param {Array} inputs - Transaction inputs
     * @returns {Buffer} 32-byte hash
     */
    static shaPrevouts(inputs) {
        const data = [];
        for (const input of inputs) {
            const txid = typeof input.txid === 'string'
                ? Buffer.from(input.txid, 'hex').reverse()
                : Buffer.from(input.txid).reverse();
            const vout = Buffer.alloc(4);
            vout.writeUInt32LE(input.vout, 0);
            data.push(txid, vout);
        }
        return sha256(Buffer.concat(data));
    }

    /**
     * Calculate sha_amounts for Taproot
     * @param {Array} prevouts - Previous outputs with values
     * @returns {Buffer} 32-byte hash
     */
    static shaAmounts(prevouts) {
        const data = [];
        for (const prevout of prevouts) {
            const value = Buffer.alloc(8);
            value.writeBigUInt64LE(BigInt(prevout.value), 0);
            data.push(value);
        }
        return sha256(Buffer.concat(data));
    }

    /**
     * Calculate sha_scriptpubkeys for Taproot
     * @param {Array} prevouts - Previous outputs with scriptPubKeys
     * @returns {Buffer} 32-byte hash
     */
    static shaScriptPubkeys(prevouts) {
        const data = [];
        for (const prevout of prevouts) {
            const script = Buffer.isBuffer(prevout.scriptPubKey)
                ? prevout.scriptPubKey
                : Buffer.from(prevout.scriptPubKey, 'hex');
            data.push(encodeVarInt(script.length), script);
        }
        return sha256(Buffer.concat(data));
    }

    /**
     * Calculate sha_sequences for Taproot
     * @param {Array} inputs - Transaction inputs
     * @returns {Buffer} 32-byte hash
     */
    static shaSequences(inputs) {
        const data = [];
        for (const input of inputs) {
            const seq = Buffer.alloc(4);
            seq.writeUInt32LE(input.sequence ?? 0xffffffff, 0);
            data.push(seq);
        }
        return sha256(Buffer.concat(data));
    }

    /**
     * Calculate sha_outputs for Taproot
     * @param {Array} outputs - Transaction outputs
     * @returns {Buffer} 32-byte hash
     */
    static shaOutputs(outputs) {
        const data = [];
        for (const output of outputs) {
            const value = Buffer.alloc(8);
            value.writeBigUInt64LE(BigInt(output.value), 0);

            const script = Buffer.isBuffer(output.scriptPubKey)
                ? output.scriptPubKey
                : Buffer.from(output.scriptPubKey, 'hex');

            data.push(value, encodeVarInt(script.length), script);
        }
        return sha256(Buffer.concat(data));
    }

    /**
     * Calculate BIP341 sighash for Taproot key-path spending
     * @param {Object} tx - Transaction object
     * @param {number} inputIndex - Input being signed
     * @param {Array} prevouts - Previous outputs (with value and scriptPubKey)
     * @param {number} [sighashType=0x00] - Sighash type (DEFAULT=0x00)
     * @param {Buffer} [annex=null] - Optional annex
     * @returns {Buffer} 32-byte sighash
     */
    static calculate(tx, inputIndex, prevouts, sighashType = SIGHASH.DEFAULT, annex = null) {
        if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
            throw new SighashError('Invalid input index', 'INVALID_INDEX');
        }

        if (prevouts.length !== tx.inputs.length) {
            throw new SighashError('Prevouts count must match inputs count', 'PREVOUT_MISMATCH');
        }

        const input = tx.inputs[inputIndex];
        const parts = [];

        // Epoch (1 byte)
        parts.push(Buffer.from([0x00]));

        // Hash type (1 byte)
        parts.push(Buffer.from([sighashType]));

        // nVersion (4 bytes)
        const version = Buffer.alloc(4);
        version.writeInt32LE(tx.version ?? 2, 0);
        parts.push(version);

        // nLockTime (4 bytes)
        const locktime = Buffer.alloc(4);
        locktime.writeUInt32LE(tx.locktime ?? 0, 0);
        parts.push(locktime);

        const baseType = sighashType & 0x1f;
        const anyoneCanPay = !!(sighashType & SIGHASH.ANYONECANPAY);

        // If not ANYONECANPAY, include aggregated data
        if (!anyoneCanPay) {
            parts.push(this.shaPrevouts(tx.inputs));
            parts.push(this.shaAmounts(prevouts));
            parts.push(this.shaScriptPubkeys(prevouts));
            parts.push(this.shaSequences(tx.inputs));
        }

        // If SIGHASH_ALL (or DEFAULT), include all outputs
        if (baseType === SIGHASH.ALL || baseType === SIGHASH.DEFAULT) {
            parts.push(this.shaOutputs(tx.outputs));
        }

        // Spend type (1 byte): 0 = key path, 1 = script path (+ annex flags)
        let spendType = 0x00;
        if (annex) {
            spendType |= 0x01;
        }
        parts.push(Buffer.from([spendType]));

        // If ANYONECANPAY, include input-specific data
        if (anyoneCanPay) {
            // outpoint
            const txid = typeof input.txid === 'string'
                ? Buffer.from(input.txid, 'hex').reverse()
                : Buffer.from(input.txid).reverse();
            const vout = Buffer.alloc(4);
            vout.writeUInt32LE(input.vout, 0);
            parts.push(txid, vout);

            // amount
            const value = Buffer.alloc(8);
            value.writeBigUInt64LE(BigInt(prevouts[inputIndex].value), 0);
            parts.push(value);

            // scriptPubKey
            const script = Buffer.isBuffer(prevouts[inputIndex].scriptPubKey)
                ? prevouts[inputIndex].scriptPubKey
                : Buffer.from(prevouts[inputIndex].scriptPubKey, 'hex');
            parts.push(encodeVarInt(script.length), script);

            // sequence
            const seq = Buffer.alloc(4);
            seq.writeUInt32LE(input.sequence ?? 0xffffffff, 0);
            parts.push(seq);
        } else {
            // input index (4 bytes)
            const idx = Buffer.alloc(4);
            idx.writeUInt32LE(inputIndex, 0);
            parts.push(idx);
        }

        // Annex hash if present
        if (annex) {
            parts.push(sha256(Buffer.concat([encodeVarInt(annex.length), annex])));
        }

        // If SIGHASH_SINGLE, include single output
        if (baseType === SIGHASH.SINGLE) {
            if (inputIndex >= tx.outputs.length) {
                throw new SighashError('No output for SIGHASH_SINGLE', 'NO_OUTPUT');
            }
            const output = tx.outputs[inputIndex];
            const value = Buffer.alloc(8);
            value.writeBigUInt64LE(BigInt(output.value), 0);
            const script = Buffer.isBuffer(output.scriptPubKey)
                ? output.scriptPubKey
                : Buffer.from(output.scriptPubKey, 'hex');
            parts.push(sha256(Buffer.concat([value, encodeVarInt(script.length), script])));
        }

        // Create tagged hash
        return taggedHash('TapSighash', Buffer.concat(parts));
    }

    /**
     * Calculate sighash for Taproot script-path spending
     * @param {Object} tx - Transaction object
     * @param {number} inputIndex - Input index
     * @param {Array} prevouts - Previous outputs
     * @param {Buffer} tapLeafHash - Leaf hash (tapleaf_hash)
     * @param {Buffer} keyVersion - Key version (0x00 for internal key)
     * @param {number} [sighashType=0x00] - Sighash type
     * @param {Buffer} [annex=null] - Optional annex
     * @returns {Buffer} 32-byte sighash
     */
    static forScriptPath(tx, inputIndex, prevouts, tapLeafHash, keyVersion = Buffer.from([0x00]), sighashType = SIGHASH.DEFAULT, annex = null) {
        // For script path, we append additional data to the key-path sighash preimage
        const keyPathSighash = this.calculate(tx, inputIndex, prevouts, sighashType, annex);

        // ext_flag = 1 for script path
        // This is a simplified implementation - full script path needs leaf data
        const extData = Buffer.concat([
            tapLeafHash,
            keyVersion,
            Buffer.from([0xff, 0xff, 0xff, 0xff]) // codesep_pos = -1
        ]);

        return taggedHash('TapSighash', Buffer.concat([
            Buffer.from([0x00, sighashType]), // epoch + hash_type
            keyPathSighash.slice(2), // Skip epoch and hash_type from key-path
            Buffer.from([0x01]), // ext_flag = 1
            extData
        ]));
    }
}

/**
 * Legacy sighash calculator (P2PKH)
 * @class LegacySighash
 */
class LegacySighash {
    /**
     * Calculate legacy sighash for P2PKH inputs
     * @param {Object} tx - Transaction object
     * @param {number} inputIndex - Input being signed
     * @param {Buffer} subscript - Subscript (scriptPubKey of UTXO)
     * @param {number} [sighashType=0x01] - Sighash type
     * @returns {Buffer} 32-byte sighash
     */
    static calculate(tx, inputIndex, subscript, sighashType = SIGHASH.ALL) {
        if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
            throw new SighashError('Invalid input index', 'INVALID_INDEX');
        }

        // Clone transaction
        const txCopy = {
            version: tx.version ?? 1,
            inputs: tx.inputs.map((input, i) => ({
                txid: input.txid,
                vout: input.vout,
                scriptSig: i === inputIndex ? subscript : Buffer.alloc(0),
                sequence: input.sequence ?? 0xffffffff
            })),
            outputs: [...tx.outputs],
            locktime: tx.locktime ?? 0
        };

        const baseType = sighashType & 0x1f;

        // Handle SIGHASH_NONE
        if (baseType === SIGHASH.NONE) {
            txCopy.outputs = [];
            for (let i = 0; i < txCopy.inputs.length; i++) {
                if (i !== inputIndex) {
                    txCopy.inputs[i].sequence = 0;
                }
            }
        }

        // Handle SIGHASH_SINGLE
        if (baseType === SIGHASH.SINGLE) {
            if (inputIndex >= tx.outputs.length) {
                // Bitcoin Core bug: return hash of 1
                const result = Buffer.alloc(32, 0);
                result[0] = 1;
                return result;
            }
            txCopy.outputs = tx.outputs.slice(0, inputIndex + 1).map((out, i) => {
                if (i < inputIndex) {
                    return { value: -1, scriptPubKey: Buffer.alloc(0) };
                }
                return out;
            });
            for (let i = 0; i < txCopy.inputs.length; i++) {
                if (i !== inputIndex) {
                    txCopy.inputs[i].sequence = 0;
                }
            }
        }

        // Handle ANYONECANPAY
        if (sighashType & SIGHASH.ANYONECANPAY) {
            txCopy.inputs = [txCopy.inputs[inputIndex]];
        }

        // Serialize and hash
        const serialized = this._serialize(txCopy);
        const sigHashBuf = Buffer.alloc(4);
        sigHashBuf.writeUInt32LE(sighashType, 0);

        return hash256(Buffer.concat([serialized, sigHashBuf]));
    }

    /**
     * Serialize transaction for legacy sighash
     * @private
     */
    static _serialize(tx) {
        const parts = [];

        // Version
        const version = Buffer.alloc(4);
        version.writeInt32LE(tx.version, 0);
        parts.push(version);

        // Inputs
        parts.push(encodeVarInt(tx.inputs.length));
        for (const input of tx.inputs) {
            const txid = typeof input.txid === 'string'
                ? Buffer.from(input.txid, 'hex').reverse()
                : Buffer.from(input.txid).reverse();
            parts.push(txid);

            const vout = Buffer.alloc(4);
            vout.writeUInt32LE(input.vout, 0);
            parts.push(vout);

            const script = Buffer.isBuffer(input.scriptSig)
                ? input.scriptSig
                : Buffer.from(input.scriptSig || '', 'hex');
            parts.push(encodeVarInt(script.length));
            parts.push(script);

            const seq = Buffer.alloc(4);
            seq.writeUInt32LE(input.sequence, 0);
            parts.push(seq);
        }

        // Outputs
        parts.push(encodeVarInt(tx.outputs.length));
        for (const output of tx.outputs) {
            const value = Buffer.alloc(8);
            if (output.value === -1) {
                value.writeBigInt64LE(BigInt(-1), 0);
            } else {
                value.writeBigUInt64LE(BigInt(output.value), 0);
            }
            parts.push(value);

            const script = Buffer.isBuffer(output.scriptPubKey)
                ? output.scriptPubKey
                : Buffer.from(output.scriptPubKey || '', 'hex');
            parts.push(encodeVarInt(script.length));
            parts.push(script);
        }

        // Locktime
        const locktime = Buffer.alloc(4);
        locktime.writeUInt32LE(tx.locktime, 0);
        parts.push(locktime);

        return Buffer.concat(parts);
    }
}

/**
 * Unified sighash calculator
 * @class SighashCalculator
 */
class SighashCalculator {
    /**
     * Calculate sighash based on input type
     * @param {Object} tx - Transaction object
     * @param {number} inputIndex - Input index
     * @param {Object} prevout - Previous output info
     * @param {number} [sighashType=0x01] - Sighash type
     * @param {Object} [options={}] - Additional options
     * @returns {Buffer} 32-byte sighash
     */
    static calculate(tx, inputIndex, prevout, sighashType = SIGHASH.ALL, options = {}) {
        const inputType = prevout.type || this._detectType(prevout);

        switch (inputType) {
            case 'p2tr':
                return BIP341.calculate(
                    tx,
                    inputIndex,
                    options.prevouts || [prevout],
                    sighashType === SIGHASH.ALL ? SIGHASH.DEFAULT : sighashType,
                    options.annex
                );

            case 'p2wpkh':
                return BIP143.forP2WPKH(
                    tx,
                    inputIndex,
                    prevout.pubkeyHash || prevout.program,
                    prevout.value,
                    sighashType
                );

            case 'p2pkh':
            default:
                return LegacySighash.calculate(
                    tx,
                    inputIndex,
                    prevout.scriptPubKey,
                    sighashType
                );
        }
    }

    /**
     * Detect input type from prevout
     * @private
     */
    static _detectType(prevout) {
        if (!prevout.scriptPubKey) return 'p2pkh';

        const script = Buffer.isBuffer(prevout.scriptPubKey)
            ? prevout.scriptPubKey
            : Buffer.from(prevout.scriptPubKey, 'hex');

        // P2TR: OP_1 <32-byte key>
        if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
            return 'p2tr';
        }

        // P2WPKH: OP_0 <20-byte hash>
        if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
            return 'p2wpkh';
        }

        // P2WSH: OP_0 <32-byte hash>
        if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
            return 'p2wsh';
        }

        // Default to P2PKH
        return 'p2pkh';
    }
}

export {
    SIGHASH,
    SighashError,
    SighashCalculator,
    BIP143,
    BIP341,
    LegacySighash,
    createP2WPKHScriptCode,
    sha256,
    hash256,
    taggedHash,
    encodeVarInt
};

export default SighashCalculator;
