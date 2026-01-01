/**
 * @fileoverview Bitcoin Script Builder
 * @description Build and parse Bitcoin scripts for all address types
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import rmd160 from '../core/crypto/hash/ripemd160.js';

/**
 * Bitcoin opcodes
 * @constant {Object}
 */
const OPCODES = {
    // Push operations
    OP_0: 0x00,
    OP_FALSE: 0x00,
    OP_PUSHDATA1: 0x4c,
    OP_PUSHDATA2: 0x4d,
    OP_PUSHDATA4: 0x4e,
    OP_1NEGATE: 0x4f,
    OP_RESERVED: 0x50,
    OP_1: 0x51,
    OP_TRUE: 0x51,
    OP_2: 0x52,
    OP_3: 0x53,
    OP_4: 0x54,
    OP_5: 0x55,
    OP_6: 0x56,
    OP_7: 0x57,
    OP_8: 0x58,
    OP_9: 0x59,
    OP_10: 0x5a,
    OP_11: 0x5b,
    OP_12: 0x5c,
    OP_13: 0x5d,
    OP_14: 0x5e,
    OP_15: 0x5f,
    OP_16: 0x60,

    // Flow control
    OP_NOP: 0x61,
    OP_VER: 0x62,
    OP_IF: 0x63,
    OP_NOTIF: 0x64,
    OP_VERIF: 0x65,
    OP_VERNOTIF: 0x66,
    OP_ELSE: 0x67,
    OP_ENDIF: 0x68,
    OP_VERIFY: 0x69,
    OP_RETURN: 0x6a,

    // Stack operations
    OP_TOALTSTACK: 0x6b,
    OP_FROMALTSTACK: 0x6c,
    OP_2DROP: 0x6d,
    OP_2DUP: 0x6e,
    OP_3DUP: 0x6f,
    OP_2OVER: 0x70,
    OP_2ROT: 0x71,
    OP_2SWAP: 0x72,
    OP_IFDUP: 0x73,
    OP_DEPTH: 0x74,
    OP_DROP: 0x75,
    OP_DUP: 0x76,
    OP_NIP: 0x77,
    OP_OVER: 0x78,
    OP_PICK: 0x79,
    OP_ROLL: 0x7a,
    OP_ROT: 0x7b,
    OP_SWAP: 0x7c,
    OP_TUCK: 0x7d,

    // Splice operations
    OP_CAT: 0x7e,
    OP_SUBSTR: 0x7f,
    OP_LEFT: 0x80,
    OP_RIGHT: 0x81,
    OP_SIZE: 0x82,

    // Bitwise logic
    OP_INVERT: 0x83,
    OP_AND: 0x84,
    OP_OR: 0x85,
    OP_XOR: 0x86,
    OP_EQUAL: 0x87,
    OP_EQUALVERIFY: 0x88,

    // Arithmetic
    OP_1ADD: 0x8b,
    OP_1SUB: 0x8c,
    OP_2MUL: 0x8d,
    OP_2DIV: 0x8e,
    OP_NEGATE: 0x8f,
    OP_ABS: 0x90,
    OP_NOT: 0x91,
    OP_0NOTEQUAL: 0x92,
    OP_ADD: 0x93,
    OP_SUB: 0x94,
    OP_MUL: 0x95,
    OP_DIV: 0x96,
    OP_MOD: 0x97,
    OP_LSHIFT: 0x98,
    OP_RSHIFT: 0x99,
    OP_BOOLAND: 0x9a,
    OP_BOOLOR: 0x9b,
    OP_NUMEQUAL: 0x9c,
    OP_NUMEQUALVERIFY: 0x9d,
    OP_NUMNOTEQUAL: 0x9e,
    OP_LESSTHAN: 0x9f,
    OP_GREATERTHAN: 0xa0,
    OP_LESSTHANOREQUAL: 0xa1,
    OP_GREATERTHANOREQUAL: 0xa2,
    OP_MIN: 0xa3,
    OP_MAX: 0xa4,
    OP_WITHIN: 0xa5,

    // Crypto
    OP_RIPEMD160: 0xa6,
    OP_SHA1: 0xa7,
    OP_SHA256: 0xa8,
    OP_HASH160: 0xa9,
    OP_HASH256: 0xaa,
    OP_CODESEPARATOR: 0xab,
    OP_CHECKSIG: 0xac,
    OP_CHECKSIGVERIFY: 0xad,
    OP_CHECKMULTISIG: 0xae,
    OP_CHECKMULTISIGVERIFY: 0xaf,

    // Expansion
    OP_NOP1: 0xb0,
    OP_CHECKLOCKTIMEVERIFY: 0xb1,
    OP_CLTV: 0xb1,
    OP_CHECKSEQUENCEVERIFY: 0xb2,
    OP_CSV: 0xb2,
    OP_NOP4: 0xb3,
    OP_NOP5: 0xb4,
    OP_NOP6: 0xb5,
    OP_NOP7: 0xb6,
    OP_NOP8: 0xb7,
    OP_NOP9: 0xb8,
    OP_NOP10: 0xb9,

    // Taproot
    OP_CHECKSIGADD: 0xba
};

// Reverse mapping for disassembly
const OPCODE_NAMES = Object.entries(OPCODES).reduce((acc, [name, code]) => {
    if (!acc[code]) acc[code] = name;
    return acc;
}, {});

/**
 * Custom error class for script operations
 * @class ScriptError
 * @extends Error
 */
class ScriptError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'ScriptError';
        this.code = code;
        this.details = details;
    }
}

/**
 * Hash160 (SHA256 + RIPEMD160)
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 20-byte hash
 */
function hash160(data) {
    const sha = createHash('sha256').update(data).digest();
    return rmd160(sha);
}

/**
 * Encode data as a push operation
 * @param {Buffer} data - Data to push
 * @returns {Buffer} Push operation bytes
 */
function encodePush(data) {
    if (!Buffer.isBuffer(data)) {
        data = Buffer.from(data, 'hex');
    }

    const len = data.length;

    if (len === 0) {
        return Buffer.from([OPCODES.OP_0]);
    }

    if (len === 1 && data[0] >= 1 && data[0] <= 16) {
        return Buffer.from([OPCODES.OP_1 + data[0] - 1]);
    }

    if (len === 1 && data[0] === 0x81) {
        return Buffer.from([OPCODES.OP_1NEGATE]);
    }

    if (len < 0x4c) {
        return Buffer.concat([Buffer.from([len]), data]);
    }

    if (len <= 0xff) {
        return Buffer.concat([Buffer.from([OPCODES.OP_PUSHDATA1, len]), data]);
    }

    if (len <= 0xffff) {
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16LE(len, 0);
        return Buffer.concat([Buffer.from([OPCODES.OP_PUSHDATA2]), lenBuf, data]);
    }

    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(len, 0);
    return Buffer.concat([Buffer.from([OPCODES.OP_PUSHDATA4]), lenBuf, data]);
}

/**
 * Script Builder class
 * @class ScriptBuilder
 */
class ScriptBuilder {
    constructor() {
        this.chunks = [];
    }

    /**
     * Add an opcode
     * @param {number} opcode - Opcode to add
     * @returns {ScriptBuilder} this
     */
    addOp(opcode) {
        this.chunks.push(Buffer.from([opcode]));
        return this;
    }

    /**
     * Push data onto the stack
     * @param {Buffer|string} data - Data to push
     * @returns {ScriptBuilder} this
     */
    pushData(data) {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'hex');
        this.chunks.push(encodePush(buf));
        return this;
    }

    /**
     * Push a number onto the stack
     * @param {number} num - Number to push
     * @returns {ScriptBuilder} this
     */
    pushNumber(num) {
        if (num === 0) {
            return this.addOp(OPCODES.OP_0);
        }
        if (num === -1) {
            return this.addOp(OPCODES.OP_1NEGATE);
        }
        if (num >= 1 && num <= 16) {
            return this.addOp(OPCODES.OP_1 + num - 1);
        }

        // Encode as minimal push
        const negative = num < 0;
        let absNum = Math.abs(num);
        const bytes = [];

        while (absNum > 0) {
            bytes.push(absNum & 0xff);
            absNum >>= 8;
        }

        if (bytes[bytes.length - 1] & 0x80) {
            bytes.push(negative ? 0x80 : 0x00);
        } else if (negative) {
            bytes[bytes.length - 1] |= 0x80;
        }

        return this.pushData(Buffer.from(bytes));
    }

    /**
     * Build the script
     * @returns {Buffer} Compiled script
     */
    build() {
        return Buffer.concat(this.chunks);
    }

    /**
     * Reset the builder
     * @returns {ScriptBuilder} this
     */
    reset() {
        this.chunks = [];
        return this;
    }

    // ===== Static factory methods =====

    /**
     * Create P2PKH scriptPubKey
     * @param {Buffer} pubkeyHash - 20-byte public key hash
     * @returns {Buffer} scriptPubKey
     */
    static createP2PKH(pubkeyHash) {
        if (pubkeyHash.length !== 20) {
            throw new ScriptError('P2PKH requires 20-byte hash', 'INVALID_HASH');
        }
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        return Buffer.concat([
            Buffer.from([OPCODES.OP_DUP, OPCODES.OP_HASH160]),
            encodePush(pubkeyHash),
            Buffer.from([OPCODES.OP_EQUALVERIFY, OPCODES.OP_CHECKSIG])
        ]);
    }

    /**
     * Create P2PKH scriptPubKey from public key
     * @param {Buffer} publicKey - Compressed or uncompressed public key
     * @returns {Buffer} scriptPubKey
     */
    static createP2PKHFromPubkey(publicKey) {
        return this.createP2PKH(hash160(publicKey));
    }

    /**
     * Create P2SH scriptPubKey
     * @param {Buffer} scriptHash - 20-byte script hash
     * @returns {Buffer} scriptPubKey
     */
    static createP2SH(scriptHash) {
        if (scriptHash.length !== 20) {
            throw new ScriptError('P2SH requires 20-byte hash', 'INVALID_HASH');
        }
        // OP_HASH160 <20 bytes> OP_EQUAL
        return Buffer.concat([
            Buffer.from([OPCODES.OP_HASH160]),
            encodePush(scriptHash),
            Buffer.from([OPCODES.OP_EQUAL])
        ]);
    }

    /**
     * Create P2WPKH scriptPubKey (SegWit v0)
     * @param {Buffer} pubkeyHash - 20-byte public key hash
     * @returns {Buffer} scriptPubKey
     */
    static createP2WPKH(pubkeyHash) {
        if (pubkeyHash.length !== 20) {
            throw new ScriptError('P2WPKH requires 20-byte hash', 'INVALID_HASH');
        }
        // OP_0 <20 bytes>
        return Buffer.concat([
            Buffer.from([OPCODES.OP_0, 0x14]),
            pubkeyHash
        ]);
    }

    /**
     * Create P2WPKH scriptPubKey from public key
     * @param {Buffer} publicKey - Compressed public key
     * @returns {Buffer} scriptPubKey
     */
    static createP2WPKHFromPubkey(publicKey) {
        return this.createP2WPKH(hash160(publicKey));
    }

    /**
     * Create P2WSH scriptPubKey (SegWit v0)
     * @param {Buffer} scriptHash - 32-byte script hash (SHA256)
     * @returns {Buffer} scriptPubKey
     */
    static createP2WSH(scriptHash) {
        if (scriptHash.length !== 32) {
            throw new ScriptError('P2WSH requires 32-byte hash', 'INVALID_HASH');
        }
        // OP_0 <32 bytes>
        return Buffer.concat([
            Buffer.from([OPCODES.OP_0, 0x20]),
            scriptHash
        ]);
    }

    /**
     * Create P2TR scriptPubKey (Taproot)
     * @param {Buffer} xOnlyPubkey - 32-byte x-only public key
     * @returns {Buffer} scriptPubKey
     */
    static createP2TR(xOnlyPubkey) {
        if (xOnlyPubkey.length !== 32) {
            throw new ScriptError('P2TR requires 32-byte x-only pubkey', 'INVALID_PUBKEY');
        }
        // OP_1 <32 bytes>
        return Buffer.concat([
            Buffer.from([OPCODES.OP_1, 0x20]),
            xOnlyPubkey
        ]);
    }

    /**
     * Create OP_RETURN output script
     * @param {Buffer|string} data - Data to embed (max 80 bytes)
     * @returns {Buffer} scriptPubKey
     */
    static createOpReturn(data) {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        if (buf.length > 80) {
            throw new ScriptError('OP_RETURN data exceeds 80 bytes', 'DATA_TOO_LONG');
        }
        return Buffer.concat([
            Buffer.from([OPCODES.OP_RETURN]),
            encodePush(buf)
        ]);
    }

    /**
     * Create P2PKH scriptSig (unlocking script)
     * @param {Buffer} signature - DER signature with sighash type
     * @param {Buffer} publicKey - Public key
     * @returns {Buffer} scriptSig
     */
    static createP2PKHScriptSig(signature, publicKey) {
        return Buffer.concat([
            encodePush(signature),
            encodePush(publicKey)
        ]);
    }

    /**
     * Create P2SH scriptSig
     * @param {Array<Buffer>} pushData - Array of data to push
     * @param {Buffer} redeemScript - The redeem script
     * @returns {Buffer} scriptSig
     */
    static createP2SHScriptSig(pushData, redeemScript) {
        const parts = pushData.map(d => encodePush(d));
        parts.push(encodePush(redeemScript));
        return Buffer.concat(parts);
    }

    /**
     * Create multisig script
     * @param {number} m - Required signatures
     * @param {Array<Buffer>} publicKeys - Public keys
     * @returns {Buffer} Multisig script
     */
    static createMultisig(m, publicKeys) {
        if (m < 1 || m > publicKeys.length) {
            throw new ScriptError('Invalid M value for multisig', 'INVALID_M');
        }
        if (publicKeys.length > 16) {
            throw new ScriptError('Too many keys for multisig', 'TOO_MANY_KEYS');
        }

        const builder = new ScriptBuilder();
        builder.pushNumber(m);
        for (const pk of publicKeys) {
            builder.pushData(pk);
        }
        builder.pushNumber(publicKeys.length);
        builder.addOp(OPCODES.OP_CHECKMULTISIG);

        return builder.build();
    }

    /**
     * Create CLTV (CheckLockTimeVerify) script
     * @param {number} locktime - Locktime value
     * @param {Buffer} pubkeyHash - Public key hash
     * @returns {Buffer} CLTV script
     */
    static createCLTV(locktime, pubkeyHash) {
        const builder = new ScriptBuilder();
        builder.pushNumber(locktime);
        builder.addOp(OPCODES.OP_CHECKLOCKTIMEVERIFY);
        builder.addOp(OPCODES.OP_DROP);
        builder.addOp(OPCODES.OP_DUP);
        builder.addOp(OPCODES.OP_HASH160);
        builder.pushData(pubkeyHash);
        builder.addOp(OPCODES.OP_EQUALVERIFY);
        builder.addOp(OPCODES.OP_CHECKSIG);
        return builder.build();
    }

    /**
     * Create CSV (CheckSequenceVerify) script
     * @param {number} sequence - Relative locktime
     * @param {Buffer} pubkeyHash - Public key hash
     * @returns {Buffer} CSV script
     */
    static createCSV(sequence, pubkeyHash) {
        const builder = new ScriptBuilder();
        builder.pushNumber(sequence);
        builder.addOp(OPCODES.OP_CHECKSEQUENCEVERIFY);
        builder.addOp(OPCODES.OP_DROP);
        builder.addOp(OPCODES.OP_DUP);
        builder.addOp(OPCODES.OP_HASH160);
        builder.pushData(pubkeyHash);
        builder.addOp(OPCODES.OP_EQUALVERIFY);
        builder.addOp(OPCODES.OP_CHECKSIG);
        return builder.build();
    }

    /**
     * Parse a script into human-readable format
     * @param {Buffer} script - Script to parse
     * @returns {Array} Array of parsed elements
     */
    static parse(script) {
        const result = [];
        let i = 0;

        while (i < script.length) {
            const opcode = script[i];

            // Direct push (1-75 bytes)
            if (opcode >= 0x01 && opcode <= 0x4b) {
                const len = opcode;
                const data = script.slice(i + 1, i + 1 + len);
                result.push({ type: 'data', value: data, hex: data.toString('hex') });
                i += 1 + len;
                continue;
            }

            // OP_PUSHDATA1
            if (opcode === OPCODES.OP_PUSHDATA1) {
                const len = script[i + 1];
                const data = script.slice(i + 2, i + 2 + len);
                result.push({ type: 'data', value: data, hex: data.toString('hex') });
                i += 2 + len;
                continue;
            }

            // OP_PUSHDATA2
            if (opcode === OPCODES.OP_PUSHDATA2) {
                const len = script.readUInt16LE(i + 1);
                const data = script.slice(i + 3, i + 3 + len);
                result.push({ type: 'data', value: data, hex: data.toString('hex') });
                i += 3 + len;
                continue;
            }

            // OP_PUSHDATA4
            if (opcode === OPCODES.OP_PUSHDATA4) {
                const len = script.readUInt32LE(i + 1);
                const data = script.slice(i + 5, i + 5 + len);
                result.push({ type: 'data', value: data, hex: data.toString('hex') });
                i += 5 + len;
                continue;
            }

            // Regular opcode
            const name = OPCODE_NAMES[opcode] || `OP_UNKNOWN_${opcode.toString(16)}`;
            result.push({ type: 'opcode', value: opcode, name });
            i += 1;
        }

        return result;
    }

    /**
     * Disassemble script to string
     * @param {Buffer} script - Script to disassemble
     * @returns {string} Human-readable script
     */
    static disassemble(script) {
        const parsed = this.parse(script);
        return parsed.map(elem => {
            if (elem.type === 'data') {
                return `<${elem.hex}>`;
            }
            return elem.name;
        }).join(' ');
    }

    /**
     * Detect script type
     * @param {Buffer} script - Script to analyze
     * @returns {Object} Script type info
     */
    static detectType(script) {
        const len = script.length;

        // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        if (len === 25 && script[0] === 0x76 && script[1] === 0xa9 &&
            script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
            return { type: 'p2pkh', hash: script.slice(3, 23) };
        }

        // P2SH: OP_HASH160 <20> OP_EQUAL
        if (len === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
            return { type: 'p2sh', hash: script.slice(2, 22) };
        }

        // P2WPKH: OP_0 <20>
        if (len === 22 && script[0] === 0x00 && script[1] === 0x14) {
            return { type: 'p2wpkh', program: script.slice(2) };
        }

        // P2WSH: OP_0 <32>
        if (len === 34 && script[0] === 0x00 && script[1] === 0x20) {
            return { type: 'p2wsh', program: script.slice(2) };
        }

        // P2TR: OP_1 <32>
        if (len === 34 && script[0] === 0x51 && script[1] === 0x20) {
            return { type: 'p2tr', program: script.slice(2) };
        }

        // OP_RETURN
        if (script[0] === 0x6a) {
            return { type: 'op_return', data: script.slice(1) };
        }

        // Multisig
        if (script[script.length - 1] === OPCODES.OP_CHECKMULTISIG) {
            const n = script[script.length - 2] - 0x50;
            const m = script[0] - 0x50;
            if (m >= 1 && m <= 16 && n >= 1 && n <= 16 && m <= n) {
                return { type: 'multisig', m, n };
            }
        }

        return { type: 'unknown' };
    }
}

export {
    OPCODES,
    OPCODE_NAMES,
    ScriptBuilder,
    ScriptError,
    encodePush,
    hash160
};

export default ScriptBuilder;
