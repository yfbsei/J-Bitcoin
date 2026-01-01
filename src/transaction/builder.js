/**
 * @fileoverview Transaction builder with signing support
 * @description Build and sign Bitcoin transactions (Legacy, SegWit, Taproot)
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { getScriptPubKey, decodeAddress, hash160 } from '../utils/address-helpers.js';
import { SighashCalculator, BIP143, BIP341, LegacySighash, SIGHASH } from './sighash.js';
import { ScriptBuilder } from './script-builder.js';
import { WitnessBuilder } from './witness-builder.js';
import { ECDSA } from '../core/crypto/signatures/ecdsa.js';
import { Schnorr } from '../core/crypto/signatures/schnorr-BIP340.js';

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
  RBF_SEQUENCE: 0xfffffffd,
  DEFAULT_LOCKTIME: 0,
  DUST_LIMIT: 546,
  SIGHASH_ALL: 0x01,
  SIGHASH_NONE: 0x02,
  SIGHASH_SINGLE: 0x03,
  SIGHASH_ANYONECANPAY: 0x80,
  SIGHASH_DEFAULT: 0x00 // Taproot
};

/**
 * Bitcoin transaction builder with SegWit/Taproot signing support
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
    this.schnorr = new Schnorr();
  }

  /**
   * Add a transaction input
   * @param {Object} input - Input details
   * @param {string} input.txid - Previous transaction ID
   * @param {number} input.vout - Output index
   * @param {number} [input.value] - UTXO value in satoshis (required for signing)
   * @param {Buffer|string} [input.scriptPubKey] - Previous output script
   * @param {string} [input.address] - Previous output address
   * @param {string} [input.type] - Address type (p2pkh, p2wpkh, p2tr)
   * @returns {TransactionBuilder} this
   */
  addInput(input) {
    if (!input.txid || typeof input.txid !== 'string') {
      throw new TransactionBuilderError('Invalid txid', 'INVALID_TXID');
    }

    if (typeof input.vout !== 'number' || input.vout < 0) {
      throw new TransactionBuilderError('Invalid vout', 'INVALID_VOUT');
    }

    // Determine type from address if not provided
    let type = input.type || input.addressType;
    let scriptPubKey = input.scriptPubKey;

    if (input.address && !type) {
      const decoded = decodeAddress(input.address);
      type = decoded.type;
    }

    if (input.address && !scriptPubKey) {
      scriptPubKey = getScriptPubKey(input.address);
    }

    this.inputs.push({
      txid: input.txid,
      vout: input.vout,
      sequence: input.sequence ?? TX_CONSTANTS.DEFAULT_SEQUENCE,
      value: input.value,
      scriptPubKey: scriptPubKey,
      address: input.address,
      type: type || 'p2wpkh',
      scriptSig: Buffer.alloc(0),
      signed: false
    });

    // Initialize witness slot
    this.witnesses.push([]);

    return this;
  }

  /**
   * Add a transaction output
   * @param {Object} output - Output details
   * @param {string} [output.address] - Destination address
   * @param {number} output.value - Amount in satoshis
   * @param {Buffer} [output.scriptPubKey] - Custom scriptPubKey
   * @returns {TransactionBuilder} this
   */
  addOutput(output) {
    if (!output.address && !output.scriptPubKey) {
      throw new TransactionBuilderError('Address or scriptPubKey required', 'MISSING_OUTPUT');
    }

    if (typeof output.value !== 'number' || output.value < 0) {
      throw new TransactionBuilderError('Invalid output value', 'INVALID_VALUE');
    }

    // Allow 0 value for OP_RETURN
    const isOpReturn = output.scriptPubKey && output.scriptPubKey[0] === 0x6a;
    if (output.value < TX_CONSTANTS.DUST_LIMIT && output.value !== 0 && !isOpReturn) {
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

  /**
   * Add an OP_RETURN output
   * @param {Buffer|string} data - Data to embed (max 80 bytes)
   * @returns {TransactionBuilder} this
   */
  addOpReturn(data) {
    const script = ScriptBuilder.createOpReturn(data);
    return this.addOutput({ value: 0, scriptPubKey: script });
  }

  /**
   * Set locktime
   * @param {number} locktime - Locktime value
   * @returns {TransactionBuilder} this
   */
  setLocktime(locktime) {
    this.locktime = locktime;
    return this;
  }

  /**
   * Set version
   * @param {number} version - Transaction version
   * @returns {TransactionBuilder} this
   */
  setVersion(version) {
    this.version = version;
    return this;
  }

  /**
   * Enable Replace-by-Fee for an input
   * @param {number} [inputIndex=null] - Specific input index, or all if null
   * @returns {TransactionBuilder} this
   */
  enableRBF(inputIndex = null) {
    if (inputIndex !== null) {
      if (inputIndex < 0 || inputIndex >= this.inputs.length) {
        throw new TransactionBuilderError('Invalid input index', 'INVALID_INDEX');
      }
      this.inputs[inputIndex].sequence = TX_CONSTANTS.RBF_SEQUENCE;
    } else {
      for (const input of this.inputs) {
        input.sequence = TX_CONSTANTS.RBF_SEQUENCE;
      }
    }
    return this;
  }

  /**
   * Set custom sequence for an input (for CSV/CLTV)
   * @param {number} inputIndex - Input index
   * @param {number} sequence - Sequence value
   * @returns {TransactionBuilder} this
   */
  setInputSequence(inputIndex, sequence) {
    if (inputIndex < 0 || inputIndex >= this.inputs.length) {
      throw new TransactionBuilderError('Invalid input index', 'INVALID_INDEX');
    }
    this.inputs[inputIndex].sequence = sequence;
    return this;
  }

  /**
   * Sign a single input
   * @param {number} inputIndex - Index of input to sign
   * @param {Buffer|string} privateKey - Private key (32 bytes)
   * @param {number} [sighashType=0x01] - Sighash type
   * @returns {Promise<TransactionBuilder>} this
   */
  async signInput(inputIndex, privateKey, sighashType = TX_CONSTANTS.SIGHASH_ALL) {
    if (inputIndex < 0 || inputIndex >= this.inputs.length) {
      throw new TransactionBuilderError('Invalid input index', 'INVALID_INDEX');
    }

    const input = this.inputs[inputIndex];

    if (input.value === undefined) {
      throw new TransactionBuilderError(
        'Input value required for signing',
        'MISSING_VALUE',
        { inputIndex }
      );
    }

    // Normalize private key
    const keyBuffer = Buffer.isBuffer(privateKey)
      ? privateKey
      : Buffer.from(privateKey, 'hex');

    // Get public key
    const publicKey = ECDSA.getPublicKey(keyBuffer, true);

    // Build transaction object for sighash
    const tx = this._buildForSigning();

    // Get prevout info
    const prevout = {
      value: input.value,
      scriptPubKey: input.scriptPubKey,
      type: input.type
    };

    const inputType = input.type || 'p2wpkh';

    switch (inputType) {
      case 'p2tr': {
        // Taproot key-path signing
        const allPrevouts = this.inputs.map((inp, i) => ({
          value: inp.value,
          scriptPubKey: inp.scriptPubKey
        }));

        const taprootSighashType = sighashType === TX_CONSTANTS.SIGHASH_ALL
          ? TX_CONSTANTS.SIGHASH_DEFAULT
          : sighashType;

        const sighash = BIP341.calculate(tx, inputIndex, allPrevouts, taprootSighashType);

        // Sign with Schnorr
        const sigResult = await this.schnorr.sign(keyBuffer, sighash);
        let signature = sigResult.signature;

        // Append sighash type if not DEFAULT
        if (taprootSighashType !== TX_CONSTANTS.SIGHASH_DEFAULT) {
          signature = Buffer.concat([signature, Buffer.from([taprootSighashType])]);
        }

        // Build P2TR key-path witness
        this.witnesses[inputIndex] = WitnessBuilder.buildP2TRKeyPath(signature);
        break;
      }

      case 'p2wpkh': {
        // SegWit P2WPKH signing
        const pubkeyHash = hash160(publicKey);
        const sighash = BIP143.forP2WPKH(tx, inputIndex, pubkeyHash, input.value, sighashType);

        // Sign with ECDSA
        const sigResult = ECDSA.sign(keyBuffer, sighash);

        // Append sighash type to DER signature
        const signature = Buffer.concat([sigResult.der, Buffer.from([sighashType])]);

        // Build P2WPKH witness
        this.witnesses[inputIndex] = WitnessBuilder.buildP2WPKH(signature, publicKey);
        break;
      }

      case 'p2wsh': {
        // SegWit P2WSH signing (requires witnessScript)
        if (!input.witnessScript) {
          throw new TransactionBuilderError(
            'P2WSH requires witnessScript',
            'MISSING_WITNESS_SCRIPT',
            { inputIndex }
          );
        }

        const witnessScript = Buffer.isBuffer(input.witnessScript)
          ? input.witnessScript
          : Buffer.from(input.witnessScript, 'hex');

        // Calculate script code with length prefix
        const scriptCode = Buffer.concat([
          this._encodeVarInt(witnessScript.length),
          witnessScript
        ]);

        const sighash = BIP143.calculate(tx, inputIndex, scriptCode, input.value, sighashType);

        // Sign with ECDSA
        const sigResult = ECDSA.sign(keyBuffer, sighash);
        const signature = Buffer.concat([sigResult.der, Buffer.from([sighashType])]);

        // Build P2WSH witness (caller should add other signatures for multisig)
        if (!this.witnesses[inputIndex] || this.witnesses[inputIndex].length === 0) {
          this.witnesses[inputIndex] = [Buffer.alloc(0)]; // OP_0 for CHECKMULTISIG bug
        }
        this.witnesses[inputIndex].push(signature);
        // Store witnessScript for finalization
        input._witnessScript = witnessScript;
        break;
      }

      case 'p2sh':
      case 'p2sh-p2pkh': {
        // Legacy P2SH (requires redeemScript)
        if (!input.redeemScript) {
          throw new TransactionBuilderError(
            'P2SH requires redeemScript',
            'MISSING_REDEEM_SCRIPT',
            { inputIndex }
          );
        }

        const redeemScript = Buffer.isBuffer(input.redeemScript)
          ? input.redeemScript
          : Buffer.from(input.redeemScript, 'hex');

        const sighash = LegacySighash.calculate(tx, inputIndex, redeemScript, sighashType);

        // Sign with ECDSA
        const sigResult = ECDSA.sign(keyBuffer, sighash);
        const signature = Buffer.concat([sigResult.der, Buffer.from([sighashType])]);

        // Build P2SH scriptSig: <sig> <pubkey> <redeemScript>
        this.inputs[inputIndex].scriptSig = ScriptBuilder.createP2SHScriptSig(
          [signature, publicKey],
          redeemScript
        );
        break;
      }

      case 'p2sh-p2wpkh': {
        // Wrapped SegWit (BIP49): P2SH containing P2WPKH
        const pubkeyHash = hash160(publicKey);

        // Create P2WPKH redeemScript: OP_0 <20 bytes>
        const redeemScript = ScriptBuilder.createP2WPKH(pubkeyHash);

        // BIP143 sighash for the inner P2WPKH
        const sighash = BIP143.forP2WPKH(tx, inputIndex, pubkeyHash, input.value, sighashType);

        // Sign with ECDSA
        const sigResult = ECDSA.sign(keyBuffer, sighash);
        const signature = Buffer.concat([sigResult.der, Buffer.from([sighashType])]);

        // scriptSig contains only the redeemScript push
        this.inputs[inputIndex].scriptSig = Buffer.concat([
          Buffer.from([redeemScript.length]),
          redeemScript
        ]);

        // Witness contains signature and public key
        this.witnesses[inputIndex] = WitnessBuilder.buildP2WPKH(signature, publicKey);
        break;
      }

      case 'p2sh-p2wsh': {
        // Wrapped SegWit P2SH-P2WSH
        if (!input.witnessScript) {
          throw new TransactionBuilderError(
            'P2SH-P2WSH requires witnessScript',
            'MISSING_WITNESS_SCRIPT',
            { inputIndex }
          );
        }

        const witnessScript = Buffer.isBuffer(input.witnessScript)
          ? input.witnessScript
          : Buffer.from(input.witnessScript, 'hex');

        // Create P2WSH redeemScript: OP_0 <32-byte SHA256 of witnessScript>
        const { createHash } = await import('node:crypto');
        const scriptHash = createHash('sha256').update(witnessScript).digest();
        const redeemScript = ScriptBuilder.createP2WSH(scriptHash);

        // Calculate script code
        const scriptCode = Buffer.concat([
          this._encodeVarInt(witnessScript.length),
          witnessScript
        ]);

        const sighash = BIP143.calculate(tx, inputIndex, scriptCode, input.value, sighashType);

        // Sign with ECDSA
        const sigResult = ECDSA.sign(keyBuffer, sighash);
        const signature = Buffer.concat([sigResult.der, Buffer.from([sighashType])]);

        // scriptSig contains only the redeemScript push
        this.inputs[inputIndex].scriptSig = Buffer.concat([
          Buffer.from([redeemScript.length]),
          redeemScript
        ]);

        // Build witness
        if (!this.witnesses[inputIndex] || this.witnesses[inputIndex].length === 0) {
          this.witnesses[inputIndex] = [Buffer.alloc(0)];
        }
        this.witnesses[inputIndex].push(signature);
        input._witnessScript = witnessScript;
        break;
      }

      case 'p2pkh':
      default: {
        // Legacy P2PKH signing
        const sighash = LegacySighash.calculate(tx, inputIndex, input.scriptPubKey, sighashType);

        // Sign with ECDSA
        const sigResult = ECDSA.sign(keyBuffer, sighash);

        // Append sighash type
        const signature = Buffer.concat([sigResult.der, Buffer.from([sighashType])]);

        // Build P2PKH scriptSig
        this.inputs[inputIndex].scriptSig = ScriptBuilder.createP2PKHScriptSig(signature, publicKey);
        break;
      }
    }

    this.inputs[inputIndex].signed = true;
    return this;
  }

  /**
   * Sign all inputs with the same private key
   * @param {Buffer|string} privateKey - Private key
   * @param {number} [sighashType=0x01] - Sighash type
   * @returns {Promise<TransactionBuilder>} this
   */
  async signAllInputs(privateKey, sighashType = TX_CONSTANTS.SIGHASH_ALL) {
    for (let i = 0; i < this.inputs.length; i++) {
      await this.signInput(i, privateKey, sighashType);
    }
    return this;
  }

  /**
   * Sign inputs with different keys
   * @param {Array<Object>} signingInfo - Array of {inputIndex, privateKey, sighashType}
   * @returns {Promise<TransactionBuilder>} this
   */
  async signInputs(signingInfo) {
    for (const info of signingInfo) {
      await this.signInput(
        info.inputIndex,
        info.privateKey,
        info.sighashType ?? TX_CONSTANTS.SIGHASH_ALL
      );
    }
    return this;
  }

  /**
   * Manually add witness data to an input
   * @param {number} inputIndex - Input index
   * @param {Array<Buffer>} witnessStack - Witness items
   * @returns {TransactionBuilder} this
   */
  addWitness(inputIndex, witnessStack) {
    if (inputIndex < 0 || inputIndex >= this.inputs.length) {
      throw new TransactionBuilderError('Invalid input index', 'INVALID_INDEX');
    }
    this.witnesses[inputIndex] = witnessStack;
    this.inputs[inputIndex].signed = true;
    return this;
  }

  /**
   * Build transaction object for signing
   * @private
   */
  _buildForSigning() {
    return {
      version: this.version,
      inputs: this.inputs.map(input => ({
        txid: input.txid,
        vout: input.vout,
        sequence: input.sequence,
        scriptSig: input.scriptSig || Buffer.alloc(0)
      })),
      outputs: this.outputs.map(output => ({
        value: output.value,
        scriptPubKey: output.scriptPubKey
      })),
      locktime: this.locktime
    };
  }

  /**
   * Build the final transaction
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

    // Check for any SegWit/Taproot inputs requiring witnesses
    const hasWitness = this.witnesses.some(w => w && w.length > 0);

    return {
      version: this.version,
      inputs: this.inputs.map(input => ({
        txid: input.txid,
        vout: input.vout,
        sequence: input.sequence,
        scriptSig: input.scriptSig || Buffer.alloc(0)
      })),
      outputs: this.outputs.map(output => ({
        value: output.value,
        scriptPubKey: output.scriptPubKey
      })),
      locktime: this.locktime,
      witnesses: hasWitness ? this.witnesses : []
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

    // Version (4 bytes LE)
    const version = Buffer.alloc(4);
    version.writeInt32LE(tx.version, 0);
    parts.push(version);

    // Check for witness data
    const hasWitness = tx.witnesses && tx.witnesses.length > 0 &&
      tx.witnesses.some(w => w && w.length > 0);

    if (hasWitness) {
      // SegWit marker and flag
      parts.push(Buffer.from([0x00, 0x01]));
    }

    // Input count
    parts.push(this._encodeVarInt(tx.inputs.length));

    // Inputs
    for (const input of tx.inputs) {
      // Txid (reversed)
      const txidBuffer = typeof input.txid === 'string'
        ? Buffer.from(input.txid, 'hex').reverse()
        : Buffer.from(input.txid).reverse();
      parts.push(txidBuffer);

      // Vout
      const vout = Buffer.alloc(4);
      vout.writeUInt32LE(input.vout, 0);
      parts.push(vout);

      // ScriptSig
      const scriptSig = input.scriptSig || Buffer.alloc(0);
      parts.push(this._encodeVarInt(scriptSig.length));
      if (scriptSig.length > 0) {
        parts.push(scriptSig);
      }

      // Sequence
      const sequence = Buffer.alloc(4);
      sequence.writeUInt32LE(input.sequence, 0);
      parts.push(sequence);
    }

    // Output count
    parts.push(this._encodeVarInt(tx.outputs.length));

    // Outputs
    for (const output of tx.outputs) {
      // Value (8 bytes LE)
      const value = Buffer.alloc(8);
      value.writeBigUInt64LE(BigInt(output.value), 0);
      parts.push(value);

      // ScriptPubKey
      const script = Buffer.isBuffer(output.scriptPubKey)
        ? output.scriptPubKey
        : Buffer.from(output.scriptPubKey, 'hex');
      parts.push(this._encodeVarInt(script.length));
      parts.push(script);
    }

    // Witness data
    if (hasWitness) {
      for (let i = 0; i < tx.inputs.length; i++) {
        const witness = tx.witnesses[i] || [];
        parts.push(this._encodeVarInt(witness.length));
        for (const item of witness) {
          const itemBuf = Buffer.isBuffer(item) ? item : Buffer.from(item, 'hex');
          parts.push(this._encodeVarInt(itemBuf.length));
          if (itemBuf.length > 0) {
            parts.push(itemBuf);
          }
        }
      }
    }

    // Locktime (4 bytes LE)
    const locktime = Buffer.alloc(4);
    locktime.writeUInt32LE(tx.locktime, 0);
    parts.push(locktime);

    return Buffer.concat(parts);
  }

  /**
   * Get serialized transaction as hex string
   * @returns {string} Hex-encoded transaction
   */
  toHex() {
    return this.serialize().toString('hex');
  }

  /**
   * Get transaction ID (txid)
   * @param {Object} [transaction=null] - Transaction object
   * @returns {string} Transaction ID in hex
   */
  getTxid(transaction = null) {
    const tx = transaction || this.build();

    // For txid, we serialize without witness data
    const txCopy = {
      ...tx,
      witnesses: []
    };

    const serialized = this.serialize(txCopy);
    const hash = createHash('sha256')
      .update(createHash('sha256').update(serialized).digest())
      .digest();

    return hash.reverse().toString('hex');
  }

  /**
   * Get witness transaction ID (wtxid)
   * @returns {string} Witness transaction ID in hex
   */
  getWtxid() {
    const serialized = this.serialize();
    const hash = createHash('sha256')
      .update(createHash('sha256').update(serialized).digest())
      .digest();

    return hash.reverse().toString('hex');
  }

  /**
   * Calculate transaction fee given fee rate
   * @param {number} [feeRate=1] - Satoshis per vbyte
   * @returns {number} Fee in satoshis
   */
  calculateFee(feeRate = 1) {
    const virtualSize = this.getVirtualSize();
    return Math.ceil(virtualSize * feeRate);
  }

  /**
   * Get virtual size (vsize) for fee calculation
   * @returns {number} Virtual size in vbytes
   */
  getVirtualSize() {
    const tx = this.build();

    // Serialize without witness
    const baseSerialized = this.serialize({ ...tx, witnesses: [] });
    const baseSize = baseSerialized.length;

    const hasWitness = tx.witnesses && tx.witnesses.length > 0 &&
      tx.witnesses.some(w => w && w.length > 0);

    if (!hasWitness) {
      return baseSize;
    }

    // Serialize with witness
    const fullSerialized = this.serialize(tx);
    const totalSize = fullSerialized.length;

    // vsize = (base_size * 3 + total_size) / 4
    return Math.ceil((baseSize * 3 + totalSize) / 4);
  }

  /**
   * Get transaction weight
   * @returns {number} Weight units
   */
  getWeight() {
    const tx = this.build();
    const baseSerialized = this.serialize({ ...tx, witnesses: [] });
    const baseSize = baseSerialized.length;

    const hasWitness = tx.witnesses && tx.witnesses.length > 0 &&
      tx.witnesses.some(w => w && w.length > 0);

    if (!hasWitness) {
      return baseSize * 4;
    }

    const fullSerialized = this.serialize(tx);
    const witnessSize = fullSerialized.length - baseSize;

    return baseSize * 3 + fullSerialized.length;
  }

  /**
   * Check if all inputs are signed
   * @returns {boolean} True if all inputs signed
   */
  isFullySigned() {
    return this.inputs.every(input => input.signed);
  }

  /**
   * Encode variable-length integer
   * @private
   */
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

  /**
   * Clone the builder
   * @returns {TransactionBuilder} Cloned builder
   */
  clone() {
    const builder = new TransactionBuilder(this.network, {
      version: this.version,
      locktime: this.locktime
    });

    builder.inputs = this.inputs.map(i => ({ ...i }));
    builder.outputs = this.outputs.map(o => ({ ...o }));
    builder.witnesses = this.witnesses.map(w => w ? [...w] : []);

    return builder;
  }

  /**
   * Reset the builder
   * @returns {TransactionBuilder} this
   */
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

export default TransactionBuilder;
