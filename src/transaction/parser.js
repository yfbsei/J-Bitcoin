/**
 * @fileoverview Transaction Parser
 * @description Parse raw Bitcoin transaction hex back into structured objects
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

/**
 * Custom error for transaction parsing
 * @class TransactionParseError
 * @extends Error
 */
class TransactionParseError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'TransactionParseError';
        this.code = code;
        this.details = details;
    }
}

/**
 * Transaction Parser class
 * @class TransactionParser
 */
class TransactionParser {
    /**
     * Parse transaction from hex string
     * @param {string} hex - Raw transaction hex
     * @returns {Object} Parsed transaction object
     */
    static fromHex(hex) {
        const buffer = Buffer.from(hex, 'hex');
        return this.fromBuffer(buffer);
    }

    /**
     * Parse transaction from buffer
     * @param {Buffer} buffer - Raw transaction bytes
     * @returns {Object} Parsed transaction object
     */
    static fromBuffer(buffer) {
        let offset = 0;

        // Version (4 bytes, LE)
        const version = buffer.readInt32LE(offset);
        offset += 4;

        // Check for witness marker
        let hasWitness = false;
        if (buffer[offset] === 0x00 && buffer[offset + 1] === 0x01) {
            hasWitness = true;
            offset += 2;
        }

        // Input count
        const inputCountResult = this._readVarInt(buffer, offset);
        const inputCount = inputCountResult.value;
        offset = inputCountResult.offset;

        // Parse inputs
        const inputs = [];
        for (let i = 0; i < inputCount; i++) {
            const inputResult = this._parseInput(buffer, offset);
            inputs.push(inputResult.input);
            offset = inputResult.offset;
        }

        // Output count
        const outputCountResult = this._readVarInt(buffer, offset);
        const outputCount = outputCountResult.value;
        offset = outputCountResult.offset;

        // Parse outputs
        const outputs = [];
        for (let i = 0; i < outputCount; i++) {
            const outputResult = this._parseOutput(buffer, offset);
            outputs.push(outputResult.output);
            offset = outputResult.offset;
        }

        // Parse witness data if present
        const witnesses = [];
        if (hasWitness) {
            for (let i = 0; i < inputCount; i++) {
                const witnessResult = this._parseWitness(buffer, offset);
                witnesses.push(witnessResult.items);
                offset = witnessResult.offset;
            }
        }

        // Locktime (4 bytes, LE)
        const locktime = buffer.readUInt32LE(offset);
        offset += 4;

        return {
            version,
            inputs,
            outputs,
            witnesses: hasWitness ? witnesses : [],
            locktime,
            hasWitness
        };
    }

    /**
     * Parse a single input
     * @private
     */
    static _parseInput(buffer, offset) {
        // txid (32 bytes, reversed)
        const txidBytes = buffer.slice(offset, offset + 32);
        const txid = Buffer.from(txidBytes).reverse().toString('hex');
        offset += 32;

        // vout (4 bytes, LE)
        const vout = buffer.readUInt32LE(offset);
        offset += 4;

        // scriptSig length
        const scriptLenResult = this._readVarInt(buffer, offset);
        const scriptLen = scriptLenResult.value;
        offset = scriptLenResult.offset;

        // scriptSig
        const scriptSig = buffer.slice(offset, offset + scriptLen);
        offset += scriptLen;

        // sequence (4 bytes, LE)
        const sequence = buffer.readUInt32LE(offset);
        offset += 4;

        return {
            input: { txid, vout, scriptSig, sequence },
            offset
        };
    }

    /**
     * Parse a single output
     * @private
     */
    static _parseOutput(buffer, offset) {
        // value (8 bytes, LE)
        const value = Number(buffer.readBigUInt64LE(offset));
        offset += 8;

        // scriptPubKey length
        const scriptLenResult = this._readVarInt(buffer, offset);
        const scriptLen = scriptLenResult.value;
        offset = scriptLenResult.offset;

        // scriptPubKey
        const scriptPubKey = buffer.slice(offset, offset + scriptLen);
        offset += scriptLen;

        return {
            output: { value, scriptPubKey },
            offset
        };
    }

    /**
     * Parse witness data
     * @private
     */
    static _parseWitness(buffer, offset) {
        const countResult = this._readVarInt(buffer, offset);
        const count = countResult.value;
        offset = countResult.offset;

        const items = [];
        for (let i = 0; i < count; i++) {
            const lenResult = this._readVarInt(buffer, offset);
            const len = lenResult.value;
            offset = lenResult.offset;

            items.push(buffer.slice(offset, offset + len));
            offset += len;
        }

        return { items, offset };
    }

    /**
     * Read variable-length integer
     * @private
     */
    static _readVarInt(buffer, offset) {
        const first = buffer[offset];

        if (first < 0xfd) {
            return { value: first, offset: offset + 1 };
        } else if (first === 0xfd) {
            return { value: buffer.readUInt16LE(offset + 1), offset: offset + 3 };
        } else if (first === 0xfe) {
            return { value: buffer.readUInt32LE(offset + 1), offset: offset + 5 };
        } else {
            return { value: Number(buffer.readBigUInt64LE(offset + 1)), offset: offset + 9 };
        }
    }

    /**
     * Get transaction ID from raw hex
     * @param {string} hex - Raw transaction hex
     * @returns {string} Transaction ID
     */
    static getTxid(hex) {
        const { createHash } = require('node:crypto');
        const buffer = Buffer.from(hex, 'hex');

        // Remove witness data for txid calculation
        const tx = this.fromBuffer(buffer);
        const noWitnessHex = this.serializeWithoutWitness(tx);

        const hash = createHash('sha256')
            .update(createHash('sha256').update(noWitnessHex).digest())
            .digest();

        return hash.reverse().toString('hex');
    }

    /**
     * Serialize transaction without witness (for txid)
     * @param {Object} tx - Parsed transaction
     * @returns {Buffer} Serialized bytes
     */
    static serializeWithoutWitness(tx) {
        const parts = [];

        // Version
        const version = Buffer.alloc(4);
        version.writeInt32LE(tx.version, 0);
        parts.push(version);

        // Inputs
        parts.push(this._encodeVarInt(tx.inputs.length));
        for (const input of tx.inputs) {
            parts.push(Buffer.from(input.txid, 'hex').reverse());
            const vout = Buffer.alloc(4);
            vout.writeUInt32LE(input.vout, 0);
            parts.push(vout);
            const scriptSig = Buffer.isBuffer(input.scriptSig) ? input.scriptSig : Buffer.from(input.scriptSig, 'hex');
            parts.push(this._encodeVarInt(scriptSig.length));
            parts.push(scriptSig);
            const seq = Buffer.alloc(4);
            seq.writeUInt32LE(input.sequence, 0);
            parts.push(seq);
        }

        // Outputs
        parts.push(this._encodeVarInt(tx.outputs.length));
        for (const output of tx.outputs) {
            const value = Buffer.alloc(8);
            value.writeBigUInt64LE(BigInt(output.value), 0);
            parts.push(value);
            const script = Buffer.isBuffer(output.scriptPubKey) ? output.scriptPubKey : Buffer.from(output.scriptPubKey, 'hex');
            parts.push(this._encodeVarInt(script.length));
            parts.push(script);
        }

        // Locktime
        const locktime = Buffer.alloc(4);
        locktime.writeUInt32LE(tx.locktime, 0);
        parts.push(locktime);

        return Buffer.concat(parts);
    }

    /**
     * Encode variable-length integer
     * @private
     */
    static _encodeVarInt(n) {
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
}

export { TransactionParser, TransactionParseError };
export default TransactionParser;
