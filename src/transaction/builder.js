/**
 * @fileoverview Transaction builder with Taproot support
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { getScriptPubKey } from '../utils/address-helpers.js';

/**
 * Custom error class for transaction building
 * @class TransactionBuilderError
 * @extends Error
 */
class TransactionBuilderError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'TransactionBuilderError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Transaction building constants
 * @constant {Object}
 */

const TX_CONSTANTS = {
  VERSION: 2,
  DEFAULT_SEQUENCE: 0xffffffff,
  DEFAULT_LOCKTIME: 0,
  DUST_LIMIT: 546,
  SIGHASH_ALL: 0x01,
  SIGHASH_NONE: 0x02,
  SIGHASH_SINGLE: 0x03,
  SIGHASH_ANYONECANPAY: 0x80
};

/**
 * Bitcoin transaction builder with SegWit/Taproot support
 * @class TransactionBuilder
 */
class TransactionBuilder {
  /**
   * Create a transaction builder
   * @param {string} [network='main'] - Network type
   * @param {Object} [options={}] - Builder options
   */
  constructor(network = 'main', options = {}) {
    this.network = network;
    this.version = options.version || TX_CONSTANTS.VERSION;
    this.locktime = options.locktime || TX_CONSTANTS.DEFAULT_LOCKTIME;
    this.inputs = [];
    this.outputs = [];
    this.witnesses = [];
  }

  /**
   * Add a transaction input
   * @param {Object} input - Input details
   * @param {string} input.txid - Previous transaction ID
   * @param {number} input.vout - Output index
   * @returns {TransactionBuilder} this
   */
  addInput(input) {
    if (!input.txid || typeof input.txid !== 'string') {
      throw new TransactionBuilderError('Invalid txid', 'INVALID_TXID');
    }

    if (typeof input.vout !== 'number' || input.vout < 0) {
      throw new TransactionBuilderError('Invalid vout', 'INVALID_VOUT');
    }

    this.inputs.push({
      txid: input.txid,
      vout: input.vout,
      sequence: input.sequence || TX_CONSTANTS.DEFAULT_SEQUENCE,
      value: input.value,
      scriptPubKey: input.scriptPubKey,
      address: input.address,
      addressType: input.addressType
    });

    return this;
  }

  /**
   * Add a transaction output
   * @param {Object} output - Output details
   * @param {string} [output.address] - Destination address
   * @param {number} output.value - Amount in satoshis
   * @returns {TransactionBuilder} this
   */
  addOutput(output) {
    if (!output.address && !output.scriptPubKey) {
      throw new TransactionBuilderError('Address or scriptPubKey required', 'MISSING_OUTPUT');
    }

    if (typeof output.value !== 'number' || output.value < 0) {
      throw new TransactionBuilderError('Invalid output value', 'INVALID_VALUE');
    }

    if (output.value < TX_CONSTANTS.DUST_LIMIT && output.value !== 0) {
      throw new TransactionBuilderError('Output below dust limit', 'DUST_OUTPUT');
    }

    let scriptPubKey = output.scriptPubKey;
    if (!scriptPubKey && output.address) {
      scriptPubKey = getScriptPubKey(output.address);
    }

    this.outputs.push({
      value: output.value,
      scriptPubKey,
      address: output.address
    });

    return this;
  }

  setLocktime(locktime) {
    this.locktime = locktime;
    return this;
  }

  setVersion(version) {
    this.version = version;
    return this;
  }

  /**
   * Build the transaction
   * @returns {Object} Built transaction object
   * @throws {TransactionBuilderError} If no inputs or outputs
   */
  build() {
    if (this.inputs.length === 0) {
      throw new TransactionBuilderError('No inputs added', 'NO_INPUTS');
    }

    if (this.outputs.length === 0) {
      throw new TransactionBuilderError('No outputs added', 'NO_OUTPUTS');
    }

    return {
      version: this.version,
      inputs: this.inputs.map(input => ({
        txid: input.txid,
        vout: input.vout,
        sequence: input.sequence,
        scriptSig: Buffer.alloc(0)
      })),
      outputs: this.outputs.map(output => ({
        value: output.value,
        scriptPubKey: output.scriptPubKey
      })),
      locktime: this.locktime,
      witnesses: this.witnesses
    };
  }

  /**
   * Serialize transaction to raw bytes
   * @param {Object} [transaction=null] - Transaction to serialize
   * @returns {Buffer} Serialized transaction
   */
  serialize(transaction = null) {
    const tx = transaction || this.build();
    const parts = [];

    const version = Buffer.alloc(4);
    version.writeUInt32LE(tx.version, 0);
    parts.push(version);

    const hasWitness = tx.witnesses && tx.witnesses.length > 0;
    if (hasWitness) {
      parts.push(Buffer.from([0x00, 0x01]));
    }

    parts.push(this._encodeVarInt(tx.inputs.length));

    for (const input of tx.inputs) {
      const txidBuffer = Buffer.from(input.txid, 'hex').reverse();
      parts.push(txidBuffer);

      const vout = Buffer.alloc(4);
      vout.writeUInt32LE(input.vout, 0);
      parts.push(vout);

      const scriptSig = input.scriptSig || Buffer.alloc(0);
      parts.push(this._encodeVarInt(scriptSig.length));
      parts.push(scriptSig);

      const sequence = Buffer.alloc(4);
      sequence.writeUInt32LE(input.sequence, 0);
      parts.push(sequence);
    }

    parts.push(this._encodeVarInt(tx.outputs.length));

    for (const output of tx.outputs) {
      const value = Buffer.alloc(8);
      value.writeBigUInt64LE(BigInt(output.value), 0);
      parts.push(value);

      const script = output.scriptPubKey;
      parts.push(this._encodeVarInt(script.length));
      parts.push(script);
    }

    if (hasWitness) {
      for (const witness of tx.witnesses) {
        parts.push(this._encodeVarInt(witness.length));
        for (const item of witness) {
          parts.push(this._encodeVarInt(item.length));
          parts.push(item);
        }
      }
    }

    const locktime = Buffer.alloc(4);
    locktime.writeUInt32LE(tx.locktime, 0);
    parts.push(locktime);

    return Buffer.concat(parts);
  }

  /**
   * Get transaction ID (txid)
   * @param {Object} [transaction=null] - Transaction object
   * @returns {string} Transaction ID in hex
   */
  getTxid(transaction = null) {
    const tx = transaction || this.build();
    const txCopy = { ...tx, witnesses: [] };

    const serialized = this.serialize(txCopy);
    const hash = createHash('sha256')
      .update(createHash('sha256').update(serialized).digest())
      .digest();

    return hash.reverse().toString('hex');
  }

  calculateFee(feeRate = 1) {
    const virtualSize = this.getVirtualSize();
    return Math.ceil(virtualSize * feeRate);
  }

  getVirtualSize() {
    const tx = this.build();
    const baseSerialized = this.serialize({ ...tx, witnesses: [] });
    const baseSize = baseSerialized.length;

    if (!tx.witnesses || tx.witnesses.length === 0) {
      return baseSize;
    }

    const fullSerialized = this.serialize(tx);
    const witnessSize = fullSerialized.length - baseSize;

    return Math.ceil(baseSize * 3 + fullSerialized.length) / 4;
  }

  _encodeVarInt(n) {
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

  clone() {
    const builder = new TransactionBuilder(this.network, {
      version: this.version,
      locktime: this.locktime
    });

    builder.inputs = [...this.inputs];
    builder.outputs = [...this.outputs];
    builder.witnesses = [...this.witnesses];

    return builder;
  }

  reset() {
    this.inputs = [];
    this.outputs = [];
    this.witnesses = [];
    this.locktime = TX_CONSTANTS.DEFAULT_LOCKTIME;
    return this;
  }
}

export {
  TransactionBuilder,
  TransactionBuilderError,
  TX_CONSTANTS
};
