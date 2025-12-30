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
