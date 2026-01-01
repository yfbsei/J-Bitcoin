/**
 * @fileoverview Witness Builder for SegWit and Taproot transactions
 * @description Build witness stacks for P2WPKH, P2WSH, P2TR key-path and script-path
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';

/**
 * Custom error class for witness operations
 * @class WitnessError
 * @extends Error
 */
class WitnessError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'WitnessError';
        this.code = code;
        this.details = details;
    }
}

/**
 * Tagged hash for Taproot
 * @param {string} tag - Hash tag
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 32-byte hash
 */
function taggedHash(tag, data) {
    const tagHash = createHash('sha256').update(tag).digest();
    return createHash('sha256').update(Buffer.concat([tagHash, tagHash, data])).digest();
}

/**
 * Encode a variable-length integer
 * @param {number} n - Number to encode
 * @returns {Buffer} VarInt bytes
 */
function encodeVarInt(n) {
    if (n < 0xfd) {
        return Buffer.from([n]);
    } else if (n <= 0xffff) {
        const buf = Buffer.alloc(3);
        buf[0] = 0xfd;
        buf.writeUInt16LE(n, 1);
        return buf;
    } else if (n <= 0xffffffff) {
        const buf = Buffer.alloc(5);
        buf[0] = 0xfe;
        buf.writeUInt32LE(n, 1);
        return buf;
    } else {
        const buf = Buffer.alloc(9);
        buf[0] = 0xff;
        buf.writeBigUInt64LE(BigInt(n), 1);
        return buf;
    }
}

/**
 * Witness Builder class
 * @class WitnessBuilder
 */
class WitnessBuilder {
    /**
     * Build P2WPKH witness stack
     * @param {Buffer} signature - DER signature with sighash type appended
     * @param {Buffer} publicKey - Compressed public key (33 bytes)
     * @returns {Array<Buffer>} Witness stack [signature, publicKey]
     */
    static buildP2WPKH(signature, publicKey) {
        if (!Buffer.isBuffer(signature)) {
            signature = Buffer.from(signature, 'hex');
        }
        if (!Buffer.isBuffer(publicKey)) {
            publicKey = Buffer.from(publicKey, 'hex');
        }

        if (publicKey.length !== 33) {
            throw new WitnessError('P2WPKH requires 33-byte compressed public key', 'INVALID_PUBKEY');
        }

        return [signature, publicKey];
    }

    /**
     * Build P2WSH witness stack
     * @param {Array<Buffer>} stackItems - Items to push (signatures, etc.)
     * @param {Buffer} witnessScript - The witness script
     * @returns {Array<Buffer>} Witness stack [...items, witnessScript]
     */
    static buildP2WSH(stackItems, witnessScript) {
        if (!Array.isArray(stackItems)) {
            throw new WitnessError('Stack items must be an array', 'INVALID_STACK');
        }

        const witness = stackItems.map(item =>
            Buffer.isBuffer(item) ? item : Buffer.from(item, 'hex')
        );

        const script = Buffer.isBuffer(witnessScript)
            ? witnessScript
            : Buffer.from(witnessScript, 'hex');

        witness.push(script);
        return witness;
    }

    /**
     * Build P2WSH multisig witness stack
     * @param {Array<Buffer>} signatures - DER signatures with sighash types
     * @param {Buffer} redeemScript - Multisig redeem script
     * @returns {Array<Buffer>} Witness stack [OP_0, ...signatures, redeemScript]
     */
    static buildP2WSHMultisig(signatures, redeemScript) {
        // OP_0 for CHECKMULTISIG bug
        const witness = [Buffer.alloc(0)];

        for (const sig of signatures) {
            witness.push(Buffer.isBuffer(sig) ? sig : Buffer.from(sig, 'hex'));
        }

        witness.push(Buffer.isBuffer(redeemScript) ? redeemScript : Buffer.from(redeemScript, 'hex'));
        return witness;
    }

    /**
     * Build P2TR key-path witness stack
     * @param {Buffer} schnorrSignature - 64 or 65 byte Schnorr signature
     * @returns {Array<Buffer>} Witness stack [signature]
     */
    static buildP2TRKeyPath(schnorrSignature) {
        if (!Buffer.isBuffer(schnorrSignature)) {
            schnorrSignature = Buffer.from(schnorrSignature, 'hex');
        }

        if (schnorrSignature.length !== 64 && schnorrSignature.length !== 65) {
            throw new WitnessError(
                'P2TR key-path requires 64 or 65 byte Schnorr signature',
                'INVALID_SIGNATURE'
            );
        }

        return [schnorrSignature];
    }

    /**
     * Build P2TR script-path witness stack
     * @param {Array<Buffer>} stackItems - Script input items
     * @param {Buffer} tapscript - The tapscript being executed
     * @param {Buffer} controlBlock - The control block
     * @returns {Array<Buffer>} Witness stack [...items, tapscript, controlBlock]
     */
    static buildP2TRScriptPath(stackItems, tapscript, controlBlock) {
        const witness = [];

        // Add stack items
        for (const item of stackItems) {
            witness.push(Buffer.isBuffer(item) ? item : Buffer.from(item, 'hex'));
        }

        // Add tapscript
        witness.push(Buffer.isBuffer(tapscript) ? tapscript : Buffer.from(tapscript, 'hex'));

        // Add control block
        witness.push(Buffer.isBuffer(controlBlock) ? controlBlock : Buffer.from(controlBlock, 'hex'));

        return witness;
    }

    /**
     * Build control block for Taproot script-path spending
     * @param {Buffer} internalPubkey - 32-byte x-only internal public key
     * @param {number} leafVersion - Leaf version (default 0xc0)
     * @param {Array<Buffer>} merklePath - Merkle path from leaf to root
     * @returns {Buffer} Control block
     */
    static buildControlBlock(internalPubkey, leafVersion = 0xc0, merklePath = []) {
        if (!Buffer.isBuffer(internalPubkey)) {
            internalPubkey = Buffer.from(internalPubkey, 'hex');
        }

        if (internalPubkey.length !== 32) {
            throw new WitnessError('Internal pubkey must be 32 bytes', 'INVALID_PUBKEY');
        }

        // First byte: leaf version with parity bit
        const parts = [Buffer.from([leafVersion]), internalPubkey];

        // Add merkle path
        for (const node of merklePath) {
            const nodeBuf = Buffer.isBuffer(node) ? node : Buffer.from(node, 'hex');
            if (nodeBuf.length !== 32) {
                throw new WitnessError('Merkle path nodes must be 32 bytes', 'INVALID_MERKLE_NODE');
            }
            parts.push(nodeBuf);
        }

        return Buffer.concat(parts);
    }

    /**
     * Calculate tapleaf hash
     * @param {Buffer} script - Tapscript
     * @param {number} leafVersion - Leaf version (default 0xc0)
     * @returns {Buffer} 32-byte tapleaf hash
     */
    static calculateTapleafHash(script, leafVersion = 0xc0) {
        if (!Buffer.isBuffer(script)) {
            script = Buffer.from(script, 'hex');
        }

        const data = Buffer.concat([
            Buffer.from([leafVersion]),
            encodeVarInt(script.length),
            script
        ]);

        return taggedHash('TapLeaf', data);
    }

    /**
     * Calculate tapbranch hash
     * @param {Buffer} left - Left child hash
     * @param {Buffer} right - Right child hash
     * @returns {Buffer} 32-byte tapbranch hash
     */
    static calculateTapbranchHash(left, right) {
        // Sort lexicographically
        if (Buffer.compare(left, right) > 0) {
            [left, right] = [right, left];
        }

        return taggedHash('TapBranch', Buffer.concat([left, right]));
    }

    /**
     * Calculate taptweak hash
     * @param {Buffer} internalPubkey - 32-byte x-only internal public key
     * @param {Buffer} [merkleRoot=null] - Optional 32-byte merkle root
     * @returns {Buffer} 32-byte tweak
     */
    static calculateTaptweak(internalPubkey, merkleRoot = null) {
        if (!Buffer.isBuffer(internalPubkey)) {
            internalPubkey = Buffer.from(internalPubkey, 'hex');
        }

        const data = merkleRoot
            ? Buffer.concat([internalPubkey, merkleRoot])
            : internalPubkey;

        return taggedHash('TapTweak', data);
    }

    /**
     * Serialize witness stack to bytes
     * @param {Array<Buffer>} witnessStack - Witness items
     * @returns {Buffer} Serialized witness
     */
    static serialize(witnessStack) {
        const parts = [encodeVarInt(witnessStack.length)];

        for (const item of witnessStack) {
            const buf = Buffer.isBuffer(item) ? item : Buffer.from(item, 'hex');
            parts.push(encodeVarInt(buf.length));
            parts.push(buf);
        }

        return Buffer.concat(parts);
    }

    /**
     * Parse serialized witness data
     * @param {Buffer} data - Serialized witness
     * @returns {Array<Buffer>} Witness stack
     */
    static parse(data) {
        const result = [];
        let offset = 0;

        // Read item count
        const countResult = this._readVarInt(data, offset);
        const count = countResult.value;
        offset = countResult.offset;

        for (let i = 0; i < count; i++) {
            const lenResult = this._readVarInt(data, offset);
            const len = lenResult.value;
            offset = lenResult.offset;

            result.push(data.slice(offset, offset + len));
            offset += len;
        }

        return result;
    }

    /**
     * Read variable-length integer
     * @private
     */
    static _readVarInt(data, offset) {
        const first = data[offset];

        if (first < 0xfd) {
            return { value: first, offset: offset + 1 };
        } else if (first === 0xfd) {
            return { value: data.readUInt16LE(offset + 1), offset: offset + 3 };
        } else if (first === 0xfe) {
            return { value: data.readUInt32LE(offset + 1), offset: offset + 5 };
        } else {
            return { value: Number(data.readBigUInt64LE(offset + 1)), offset: offset + 9 };
        }
    }

    /**
     * Validate witness stack for a given output type
     * @param {Array<Buffer>} witnessStack - Witness to validate
     * @param {string} outputType - Output type (p2wpkh, p2wsh, p2tr)
     * @returns {Object} Validation result
     */
    static validate(witnessStack, outputType) {
        if (!Array.isArray(witnessStack) || witnessStack.length === 0) {
            return { valid: false, error: 'Empty witness stack' };
        }

        switch (outputType) {
            case 'p2wpkh':
                if (witnessStack.length !== 2) {
                    return { valid: false, error: 'P2WPKH requires exactly 2 items' };
                }
                if (witnessStack[1].length !== 33) {
                    return { valid: false, error: 'P2WPKH requires 33-byte compressed pubkey' };
                }
                return { valid: true };

            case 'p2wsh':
                if (witnessStack.length < 1) {
                    return { valid: false, error: 'P2WSH requires at least witness script' };
                }
                return { valid: true };

            case 'p2tr':
                // Key-path: 1 item (signature)
                // Script-path: 2+ items (inputs + script + control block)
                if (witnessStack.length === 1) {
                    const sig = witnessStack[0];
                    if (sig.length !== 64 && sig.length !== 65) {
                        return { valid: false, error: 'P2TR key-path requires 64/65 byte signature' };
                    }
                }
                return { valid: true };

            default:
                return { valid: false, error: `Unknown output type: ${outputType}` };
        }
    }
}

export {
    WitnessBuilder,
    WitnessError,
    taggedHash,
    encodeVarInt
};

export default WitnessBuilder;
