/**
 * @fileoverview UTXO management with selection strategies
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

class UTXOManagerError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'UTXOManagerError';
    this.code = code;
    this.details = details;
  }
}

const UTXO_CONSTANTS = {
  MAX_UTXOS_PER_TRANSACTION: 100,
  MIN_UTXO_VALUE: 546,
  MAX_SELECTION_ATTEMPTS: 1000,
  CONSOLIDATION_THRESHOLD: 100,
  DEFAULT_FEE_RATE: 10,
  MIN_FEE_RATE: 1,
  MAX_FEE_RATE: 1000
};

const INPUT_SIZES = {
  p2pkh: 148,
  p2sh: 91,
  p2wpkh: 68,
  p2wsh: 91,
  p2tr: 57.5
};

const OUTPUT_SIZES = {
  p2pkh: 34,
  p2sh: 32,
  p2wpkh: 31,
  p2wsh: 43,
  p2tr: 43
};

class UTXOManager {
  constructor(utxos = []) {
    this.utxos = [];
    this.feeCache = new Map();

    for (const utxo of utxos) {
      this.addUTXO(utxo);
    }
  }

  addUTXO(utxo) {
    if (!utxo.txid || typeof utxo.txid !== 'string') {
      throw new UTXOManagerError('Invalid UTXO txid', 'INVALID_TXID');
    }

    if (typeof utxo.vout !== 'number' || utxo.vout < 0) {
      throw new UTXOManagerError('Invalid UTXO vout', 'INVALID_VOUT');
    }

    if (typeof utxo.value !== 'number' || utxo.value < 0) {
      throw new UTXOManagerError('Invalid UTXO value', 'INVALID_VALUE');
    }

    this.utxos.push({
      txid: utxo.txid,
      vout: utxo.vout,
      value: utxo.value,
      scriptPubKey: utxo.scriptPubKey,
      address: utxo.address,
      type: utxo.type || 'p2wpkh',
      confirmations: utxo.confirmations || 0,
      isSpent: false
    });

    return this;
  }

  removeUTXO(txid, vout) {
    const index = this.utxos.findIndex(u => u.txid === txid && u.vout === vout);
    if (index !== -1) {
      this.utxos.splice(index, 1);
    }
    return this;
  }

  markSpent(txid, vout) {
    const utxo = this.utxos.find(u => u.txid === txid && u.vout === vout);
    if (utxo) {
      utxo.isSpent = true;
    }
    return this;
  }

  getBalance() {
    return this.utxos
      .filter(u => !u.isSpent)
      .reduce((sum, u) => sum + u.value, 0);
  }

  getAvailableUTXOs() {
    return this.utxos.filter(u => !u.isSpent);
  }

  selectUTXOs(targetAmount, feeRate = UTXO_CONSTANTS.DEFAULT_FEE_RATE, strategy = 'optimal') {
    const available = this.getAvailableUTXOs();

    if (available.length === 0) {
      throw new UTXOManagerError('No available UTXOs', 'NO_UTXOS');
    }

    switch (strategy) {
      case 'largest':
        return this._selectLargestFirst(available, targetAmount, feeRate);
      case 'smallest':
        return this._selectSmallestFirst(available, targetAmount, feeRate);
      case 'oldest':
        return this._selectOldestFirst(available, targetAmount, feeRate);
      case 'optimal':
      default:
        return this._selectOptimal(available, targetAmount, feeRate);
    }
  }

  _selectLargestFirst(utxos, targetAmount, feeRate) {
    const sorted = [...utxos].sort((a, b) => b.value - a.value);
    return this._accumulate(sorted, targetAmount, feeRate);
  }

  _selectSmallestFirst(utxos, targetAmount, feeRate) {
    const sorted = [...utxos].sort((a, b) => a.value - b.value);
    return this._accumulate(sorted, targetAmount, feeRate);
  }

  _selectOldestFirst(utxos, targetAmount, feeRate) {
    const sorted = [...utxos].sort((a, b) => b.confirmations - a.confirmations);
    return this._accumulate(sorted, targetAmount, feeRate);
  }

  _selectOptimal(utxos, targetAmount, feeRate) {
    const exactMatch = utxos.find(u => {
      const fee = this._estimateFee([u], 2, feeRate);
      return u.value === targetAmount + fee;
    });

    if (exactMatch) {
      return {
        utxos: [exactMatch],
        totalValue: exactMatch.value,
        fee: this._estimateFee([exactMatch], 2, feeRate),
        change: 0
      };
    }

    return this._selectLargestFirst(utxos, targetAmount, feeRate);
  }

  _accumulate(sortedUtxos, targetAmount, feeRate) {
    const selected = [];
    let totalValue = 0;

    for (const utxo of sortedUtxos) {
      selected.push(utxo);
      totalValue += utxo.value;

      const fee = this._estimateFee(selected, 2, feeRate);
      const requiredAmount = targetAmount + fee;

      if (totalValue >= requiredAmount) {
        const change = totalValue - requiredAmount;
        return {
          utxos: selected,
          totalValue,
          fee,
          change: change >= UTXO_CONSTANTS.MIN_UTXO_VALUE ? change : 0
        };
      }

      if (selected.length >= UTXO_CONSTANTS.MAX_UTXOS_PER_TRANSACTION) {
        break;
      }
    }

    throw new UTXOManagerError(
      `Insufficient funds: have ${totalValue}, need ${targetAmount}`,
      'INSUFFICIENT_FUNDS',
      { available: totalValue, required: targetAmount }
    );
  }

  _estimateFee(inputs, outputCount, feeRate) {
    const baseSize = 10;
    let inputSize = 0;

    for (const input of inputs) {
      inputSize += INPUT_SIZES[input.type] || INPUT_SIZES.p2wpkh;
    }

    const outputSize = outputCount * OUTPUT_SIZES.p2wpkh;
    const virtualSize = baseSize + inputSize + outputSize;

    return Math.ceil(virtualSize * feeRate);
  }

  estimateFee(inputCount, outputCount, feeRate = UTXO_CONSTANTS.DEFAULT_FEE_RATE, inputType = 'p2wpkh') {
    const baseSize = 10;
    const inputSize = inputCount * (INPUT_SIZES[inputType] || INPUT_SIZES.p2wpkh);
    const outputSize = outputCount * OUTPUT_SIZES.p2wpkh;
    const virtualSize = baseSize + inputSize + outputSize;

    return Math.ceil(virtualSize * feeRate);
  }

  shouldConsolidate() {
    const available = this.getAvailableUTXOs();
    return available.length >= UTXO_CONSTANTS.CONSOLIDATION_THRESHOLD;
  }

  getConsolidationUTXOs(maxCount = 50) {
    const available = this.getAvailableUTXOs();
    const sorted = [...available].sort((a, b) => a.value - b.value);
    return sorted.slice(0, maxCount);
  }

  toJSON() {
    return {
      utxoCount: this.utxos.length,
      balance: this.getBalance(),
      utxos: this.utxos.map(u => ({
        txid: u.txid,
        vout: u.vout,
        value: u.value,
        type: u.type,
        isSpent: u.isSpent
      }))
    };
  }

  clear() {
    this.utxos = [];
    this.feeCache.clear();
    return this;
  }
}

export {
  UTXOManager,
  UTXOManagerError,
  UTXO_CONSTANTS,
  INPUT_SIZES,
  OUTPUT_SIZES
};
