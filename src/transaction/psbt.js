/**
 * @fileoverview PSBT (Partially Signed Bitcoin Transaction) implementation
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';

class PSBTError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'PSBTError';
    this.code = code;
    this.details = details;
  }
}

const PSBT_CONSTANTS = {
  MAGIC: Buffer.from([0x70, 0x73, 0x62, 0x74, 0xff]),
  GLOBAL_UNSIGNED_TX: 0x00,
  GLOBAL_XPUB: 0x01,
  IN_NON_WITNESS_UTXO: 0x00,
  IN_WITNESS_UTXO: 0x01,
  IN_PARTIAL_SIG: 0x02,
  IN_SIGHASH_TYPE: 0x03,
  IN_REDEEM_SCRIPT: 0x04,
  IN_WITNESS_SCRIPT: 0x05,
  IN_FINAL_SCRIPTSIG: 0x07,
  IN_FINAL_SCRIPTWITNESS: 0x08,
  IN_TAP_KEY_SIG: 0x13,
  IN_TAP_INTERNAL_KEY: 0x17,
  OUT_REDEEM_SCRIPT: 0x00,
  OUT_WITNESS_SCRIPT: 0x01,
  OUT_TAP_INTERNAL_KEY: 0x05,
  OUT_TAP_TREE: 0x06
};

class PSBTKeyValue {
  constructor(keyType, keyData, value) {
    this.keyType = keyType;
    this.keyData = keyData;
    this.value = value;
  }

  serialize() {
    const keyLen = 1 + this.keyData.length;
    const parts = [
      this._encodeVarInt(keyLen),
      Buffer.from([this.keyType]),
      this.keyData,
      this._encodeVarInt(this.value.length),
      this.value
    ];
    return Buffer.concat(parts);
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
}

class PSBT {
  constructor() {
    this.global = {
      unsignedTx: null,
      xpubs: new Map()
    };
    this.inputs = [];
    this.outputs = [];
  }

  /**
   * Parse PSBT from raw buffer
   * @param {Buffer} data - Raw PSBT bytes
   * @returns {PSBT} Parsed PSBT
   */
  static fromBuffer(data) {
    if (!Buffer.isBuffer(data)) {
      data = Buffer.from(data);
    }

    // Check magic bytes
    const magic = data.slice(0, 5);
    if (!magic.equals(PSBT_CONSTANTS.MAGIC)) {
      throw new PSBTError('Invalid PSBT magic bytes', 'INVALID_MAGIC');
    }

    const psbt = new PSBT();
    let offset = 5;

    // Parse global map
    const globalResult = PSBT._parseMap(data, offset);
    offset = globalResult.offset;

    for (const [key, value] of globalResult.entries) {
      const keyType = key[0];
      const keyData = key.slice(1);

      if (keyType === PSBT_CONSTANTS.GLOBAL_UNSIGNED_TX) {
        psbt.global.unsignedTx = PSBT._parseUnsignedTx(value);
      } else if (keyType === PSBT_CONSTANTS.GLOBAL_XPUB) {
        psbt.global.xpubs.set(keyData.toString('hex'), value);
      }
    }

    if (!psbt.global.unsignedTx) {
      throw new PSBTError('PSBT missing unsigned transaction', 'MISSING_TX');
    }

    const inputCount = psbt.global.unsignedTx.inputs.length;
    const outputCount = psbt.global.unsignedTx.outputs.length;

    // Parse input maps
    for (let i = 0; i < inputCount; i++) {
      const inputResult = PSBT._parseMap(data, offset);
      offset = inputResult.offset;

      const input = {
        nonWitnessUtxo: null,
        witnessUtxo: null,
        partialSigs: new Map(),
        sighashType: null,
        redeemScript: null,
        witnessScript: null,
        finalScriptSig: null,
        finalScriptWitness: null,
        tapKeySig: null,
        tapInternalKey: null
      };

      for (const [key, value] of inputResult.entries) {
        const keyType = key[0];
        const keyData = key.slice(1);

        switch (keyType) {
          case PSBT_CONSTANTS.IN_NON_WITNESS_UTXO:
            input.nonWitnessUtxo = value;
            break;
          case PSBT_CONSTANTS.IN_WITNESS_UTXO:
            input.witnessUtxo = PSBT._parseWitnessUtxo(value);
            break;
          case PSBT_CONSTANTS.IN_PARTIAL_SIG:
            input.partialSigs.set(keyData.toString('hex'), value);
            break;
          case PSBT_CONSTANTS.IN_SIGHASH_TYPE:
            input.sighashType = value.readUInt32LE(0);
            break;
          case PSBT_CONSTANTS.IN_REDEEM_SCRIPT:
            input.redeemScript = value;
            break;
          case PSBT_CONSTANTS.IN_WITNESS_SCRIPT:
            input.witnessScript = value;
            break;
          case PSBT_CONSTANTS.IN_FINAL_SCRIPTSIG:
            input.finalScriptSig = value;
            break;
          case PSBT_CONSTANTS.IN_FINAL_SCRIPTWITNESS:
            input.finalScriptWitness = PSBT._parseWitness(value);
            break;
          case PSBT_CONSTANTS.IN_TAP_KEY_SIG:
            input.tapKeySig = value;
            break;
          case PSBT_CONSTANTS.IN_TAP_INTERNAL_KEY:
            input.tapInternalKey = value;
            break;
        }
      }

      psbt.inputs.push(input);
    }

    // Parse output maps
    for (let i = 0; i < outputCount; i++) {
      const outputResult = PSBT._parseMap(data, offset);
      offset = outputResult.offset;

      const output = {
        redeemScript: null,
        witnessScript: null,
        tapInternalKey: null,
        tapTree: null
      };

      for (const [key, value] of outputResult.entries) {
        const keyType = key[0];

        switch (keyType) {
          case PSBT_CONSTANTS.OUT_REDEEM_SCRIPT:
            output.redeemScript = value;
            break;
          case PSBT_CONSTANTS.OUT_WITNESS_SCRIPT:
            output.witnessScript = value;
            break;
          case PSBT_CONSTANTS.OUT_TAP_INTERNAL_KEY:
            output.tapInternalKey = value;
            break;
          case PSBT_CONSTANTS.OUT_TAP_TREE:
            output.tapTree = value;
            break;
        }
      }

      psbt.outputs.push(output);
    }

    return psbt;
  }

  /**
   * Parse PSBT from base64 string
   * @param {string} base64 - Base64-encoded PSBT
   * @returns {PSBT} Parsed PSBT
   */
  static fromBase64(base64) {
    const data = Buffer.from(base64, 'base64');
    return PSBT.fromBuffer(data);
  }

  /**
   * Parse PSBT from hex string
   * @param {string} hex - Hex-encoded PSBT
   * @returns {PSBT} Parsed PSBT
   */
  static fromHex(hex) {
    const data = Buffer.from(hex, 'hex');
    return PSBT.fromBuffer(data);
  }

  /**
   * Parse a key-value map from PSBT data
   * @private
   */
  static _parseMap(data, offset) {
    const entries = [];

    while (offset < data.length) {
      // Read key length
      const keyLenResult = PSBT._readVarInt(data, offset);
      const keyLen = keyLenResult.value;
      offset = keyLenResult.offset;

      // Separator
      if (keyLen === 0) {
        break;
      }

      // Read key
      const key = data.slice(offset, offset + keyLen);
      offset += keyLen;

      // Read value length
      const valueLenResult = PSBT._readVarInt(data, offset);
      const valueLen = valueLenResult.value;
      offset = valueLenResult.offset;

      // Read value
      const value = data.slice(offset, offset + valueLen);
      offset += valueLen;

      entries.push([key, value]);
    }

    return { entries, offset };
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
   * Parse unsigned transaction from PSBT
   * @private
   */
  static _parseUnsignedTx(data) {
    let offset = 0;

    const version = data.readUInt32LE(offset);
    offset += 4;

    // Input count
    const inputCountResult = PSBT._readVarInt(data, offset);
    const inputCount = inputCountResult.value;
    offset = inputCountResult.offset;

    const inputs = [];
    for (let i = 0; i < inputCount; i++) {
      const hash = data.slice(offset, offset + 32);
      offset += 32;

      const index = data.readUInt32LE(offset);
      offset += 4;

      // scriptSig length (should be 0)
      const scriptLenResult = PSBT._readVarInt(data, offset);
      offset = scriptLenResult.offset + scriptLenResult.value;

      const sequence = data.readUInt32LE(offset);
      offset += 4;

      inputs.push({ hash, index, sequence });
    }

    // Output count
    const outputCountResult = PSBT._readVarInt(data, offset);
    const outputCount = outputCountResult.value;
    offset = outputCountResult.offset;

    const outputs = [];
    for (let i = 0; i < outputCount; i++) {
      const amount = Number(data.readBigUInt64LE(offset));
      offset += 8;

      const scriptLenResult = PSBT._readVarInt(data, offset);
      const scriptLen = scriptLenResult.value;
      offset = scriptLenResult.offset;

      const script = data.slice(offset, offset + scriptLen);
      offset += scriptLen;

      outputs.push({ amount, script });
    }

    const locktime = data.readUInt32LE(offset);

    return { version, inputs, outputs, locktime };
  }

  /**
   * Parse witness UTXO
   * @private
   */
  static _parseWitnessUtxo(data) {
    let offset = 0;

    const amount = Number(data.readBigUInt64LE(offset));
    offset += 8;

    const scriptLenResult = PSBT._readVarInt(data, offset);
    const scriptLen = scriptLenResult.value;
    offset = scriptLenResult.offset;

    const scriptPubKey = data.slice(offset, offset + scriptLen);

    return { amount, scriptPubKey };
  }

  /**
   * Parse witness stack
   * @private
   */
  static _parseWitness(data) {
    const items = [];
    let offset = 0;

    const countResult = PSBT._readVarInt(data, offset);
    const count = countResult.value;
    offset = countResult.offset;

    for (let i = 0; i < count; i++) {
      const lenResult = PSBT._readVarInt(data, offset);
      const len = lenResult.value;
      offset = lenResult.offset;

      items.push(data.slice(offset, offset + len));
      offset += len;
    }

    return items;
  }

  /**
   * Export PSBT as base64 string
   * @returns {string} Base64-encoded PSBT
   */
  toBase64() {
    return this.serialize().toString('base64');
  }

  /**
   * Export PSBT as hex string
   * @returns {string} Hex-encoded PSBT
   */
  toHex() {
    return this.serialize().toString('hex');
  }

  static fromTransaction(transaction) {
    const psbt = new PSBT();

    psbt.global.unsignedTx = {
      version: transaction.version,
      inputs: transaction.inputs.map(input => ({
        hash: Buffer.from(input.txid, 'hex').reverse(),
        index: input.vout,
        sequence: input.sequence || 0xffffffff
      })),
      outputs: transaction.outputs.map(output => ({
        amount: output.value,
        script: output.scriptPubKey
      })),
      locktime: transaction.locktime || 0
    };

    for (let i = 0; i < transaction.inputs.length; i++) {
      psbt.inputs.push({
        nonWitnessUtxo: null,
        witnessUtxo: null,
        partialSigs: new Map(),
        sighashType: null,
        redeemScript: null,
        witnessScript: null,
        finalScriptSig: null,
        finalScriptWitness: null,
        tapKeySig: null,
        tapInternalKey: null
      });
    }

    for (let i = 0; i < transaction.outputs.length; i++) {
      psbt.outputs.push({
        redeemScript: null,
        witnessScript: null,
        tapInternalKey: null,
        tapTree: null
      });
    }

    return psbt;
  }

  addInput(inputData) {
    this.inputs.push({
      nonWitnessUtxo: inputData.nonWitnessUtxo || null,
      witnessUtxo: inputData.witnessUtxo || null,
      partialSigs: new Map(),
      sighashType: inputData.sighashType || null,
      redeemScript: inputData.redeemScript || null,
      witnessScript: inputData.witnessScript || null,
      finalScriptSig: null,
      finalScriptWitness: null,
      tapKeySig: inputData.tapKeySig || null,
      tapInternalKey: inputData.tapInternalKey || null
    });

    return this.inputs.length - 1;
  }

  addOutput(outputData) {
    this.outputs.push({
      redeemScript: outputData.redeemScript || null,
      witnessScript: outputData.witnessScript || null,
      tapInternalKey: outputData.tapInternalKey || null,
      tapTree: outputData.tapTree || null
    });

    return this.outputs.length - 1;
  }

  setWitnessUtxo(inputIndex, witnessUtxo) {
    if (inputIndex < 0 || inputIndex >= this.inputs.length) {
      throw new PSBTError('Invalid input index', 'INVALID_INDEX');
    }

    this.inputs[inputIndex].witnessUtxo = witnessUtxo;
    return this;
  }

  addPartialSignature(inputIndex, pubkey, signature) {
    if (inputIndex < 0 || inputIndex >= this.inputs.length) {
      throw new PSBTError('Invalid input index', 'INVALID_INDEX');
    }

    const pubkeyHex = Buffer.isBuffer(pubkey) ? pubkey.toString('hex') : pubkey;
    this.inputs[inputIndex].partialSigs.set(pubkeyHex, signature);

    return this;
  }

  setTapKeySig(inputIndex, signature) {
    if (inputIndex < 0 || inputIndex >= this.inputs.length) {
      throw new PSBTError('Invalid input index', 'INVALID_INDEX');
    }

    this.inputs[inputIndex].tapKeySig = signature;
    return this;
  }

  finalizeInput(inputIndex) {
    if (inputIndex < 0 || inputIndex >= this.inputs.length) {
      throw new PSBTError('Invalid input index', 'INVALID_INDEX');
    }

    const input = this.inputs[inputIndex];

    if (input.tapKeySig) {
      input.finalScriptWitness = [input.tapKeySig];
      return this;
    }

    if (input.partialSigs.size > 0) {
      const [pubkey, sig] = [...input.partialSigs.entries()][0];
      input.finalScriptWitness = [
        Buffer.from(sig),
        Buffer.from(pubkey, 'hex')
      ];
      return this;
    }

    throw new PSBTError('Cannot finalize input without signatures', 'NO_SIGNATURES');
  }

  finalizeAllInputs() {
    for (let i = 0; i < this.inputs.length; i++) {
      this.finalizeInput(i);
    }
    return this;
  }

  isFinalized() {
    return this.inputs.every(input =>
      input.finalScriptSig !== null || input.finalScriptWitness !== null
    );
  }

  extractTransaction() {
    if (!this.isFinalized()) {
      throw new PSBTError('PSBT not finalized', 'NOT_FINALIZED');
    }

    return {
      version: this.global.unsignedTx.version,
      inputs: this.global.unsignedTx.inputs.map((input, i) => ({
        txid: input.hash.reverse().toString('hex'),
        vout: input.index,
        sequence: input.sequence,
        scriptSig: this.inputs[i].finalScriptSig || Buffer.alloc(0)
      })),
      outputs: this.global.unsignedTx.outputs.map(output => ({
        value: output.amount,
        scriptPubKey: output.script
      })),
      locktime: this.global.unsignedTx.locktime,
      witnesses: this.inputs.map(input => input.finalScriptWitness || [])
    };
  }

  serialize() {
    const parts = [PSBT_CONSTANTS.MAGIC];

    parts.push(this._serializeGlobal());

    for (let i = 0; i < this.inputs.length; i++) {
      parts.push(this._serializeInput(i));
    }

    for (let i = 0; i < this.outputs.length; i++) {
      parts.push(this._serializeOutput(i));
    }

    return Buffer.concat(parts);
  }

  _serializeGlobal() {
    const fields = [];

    if (this.global.unsignedTx) {
      const txData = this._serializeUnsignedTransaction();
      fields.push(new PSBTKeyValue(
        PSBT_CONSTANTS.GLOBAL_UNSIGNED_TX,
        Buffer.alloc(0),
        txData
      ));
    }

    const serializedFields = fields.map(field => field.serialize());
    serializedFields.push(Buffer.from([0x00]));

    return Buffer.concat(serializedFields);
  }

  _serializeInput(index) {
    const input = this.inputs[index];
    const fields = [];

    if (input.witnessUtxo) {
      fields.push(new PSBTKeyValue(
        PSBT_CONSTANTS.IN_WITNESS_UTXO,
        Buffer.alloc(0),
        this._serializeWitnessUtxo(input.witnessUtxo)
      ));
    }

    for (const [pubkey, sig] of input.partialSigs) {
      fields.push(new PSBTKeyValue(
        PSBT_CONSTANTS.IN_PARTIAL_SIG,
        Buffer.from(pubkey, 'hex'),
        sig
      ));
    }

    if (input.tapKeySig) {
      fields.push(new PSBTKeyValue(
        PSBT_CONSTANTS.IN_TAP_KEY_SIG,
        Buffer.alloc(0),
        input.tapKeySig
      ));
    }

    if (input.finalScriptWitness) {
      fields.push(new PSBTKeyValue(
        PSBT_CONSTANTS.IN_FINAL_SCRIPTWITNESS,
        Buffer.alloc(0),
        this._serializeWitness(input.finalScriptWitness)
      ));
    }

    const serializedFields = fields.map(field => field.serialize());
    serializedFields.push(Buffer.from([0x00]));

    return Buffer.concat(serializedFields);
  }

  _serializeOutput(index) {
    const output = this.outputs[index];
    const fields = [];

    if (output.tapInternalKey) {
      fields.push(new PSBTKeyValue(
        PSBT_CONSTANTS.OUT_TAP_INTERNAL_KEY,
        Buffer.alloc(0),
        output.tapInternalKey
      ));
    }

    const serializedFields = fields.map(field => field.serialize());
    serializedFields.push(Buffer.from([0x00]));

    return Buffer.concat(serializedFields);
  }

  _serializeUnsignedTransaction() {
    const parts = [];
    const tx = this.global.unsignedTx;

    const version = Buffer.alloc(4);
    version.writeUInt32LE(tx.version, 0);
    parts.push(version);

    parts.push(this._encodeVarInt(tx.inputs.length));
    for (const input of tx.inputs) {
      parts.push(input.hash);
      const index = Buffer.alloc(4);
      index.writeUInt32LE(input.index, 0);
      parts.push(index);
      parts.push(Buffer.from([0x00]));
      const sequence = Buffer.alloc(4);
      sequence.writeUInt32LE(input.sequence, 0);
      parts.push(sequence);
    }

    parts.push(this._encodeVarInt(tx.outputs.length));
    for (const output of tx.outputs) {
      const amount = Buffer.alloc(8);
      amount.writeBigUInt64LE(BigInt(output.amount), 0);
      parts.push(amount);
      parts.push(this._encodeVarInt(output.script.length));
      parts.push(output.script);
    }

    const locktime = Buffer.alloc(4);
    locktime.writeUInt32LE(tx.locktime, 0);
    parts.push(locktime);

    return Buffer.concat(parts);
  }

  _serializeWitnessUtxo(utxo) {
    const amount = Buffer.alloc(8);
    amount.writeBigUInt64LE(BigInt(utxo.amount), 0);
    const scriptLen = this._encodeVarInt(utxo.scriptPubKey.length);
    return Buffer.concat([amount, scriptLen, utxo.scriptPubKey]);
  }

  _serializeWitness(witness) {
    const parts = [this._encodeVarInt(witness.length)];
    for (const item of witness) {
      parts.push(this._encodeVarInt(item.length));
      parts.push(item);
    }
    return Buffer.concat(parts);
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
    const cloned = new PSBT();
    cloned.global = JSON.parse(JSON.stringify(this.global));
    cloned.inputs = this.inputs.map(input => ({ ...input }));
    cloned.outputs = this.outputs.map(output => ({ ...output }));
    return cloned;
  }
}

export { PSBT, PSBTError, PSBTKeyValue, PSBT_CONSTANTS };
