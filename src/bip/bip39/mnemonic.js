/**
 * @fileoverview BIP39 mnemonic phrase generation and seed derivation
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash, randomBytes, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import ENGLISH_WORDLIST from './wordList_en.js';

const BIP39_CONSTANTS = {
  ENTROPY_BITS: 128,
  CHECKSUM_BITS: 4,
  WORD_COUNT: 12,
  BITS_PER_WORD: 11,
  PBKDF2_ITERATIONS: 2048,
  SEED_LENGTH_BYTES: 64,
  MNEMONIC_SALT_PREFIX: 'mnemonic',
  MIN_ENTROPY_BYTES: 16,
  MAX_ENTROPY_BYTES: 64,
  VALID_WORD_COUNTS: [12, 15, 18, 21, 24],
  ENTROPY_QUALITY_THRESHOLD: 0.4
};

function normalizeUnicode(text, form = 'NFKD') {
  if (typeof text !== 'string') {
    throw new Error('Input must be a string for Unicode normalization');
  }
  return text.normalize(form);
}

function validateEntropyQuality(entropy) {
  const bytes = Array.from(entropy);
  const byteFrequency = new Map();

  for (const byte of bytes) {
    byteFrequency.set(byte, (byteFrequency.get(byte) || 0) + 1);
  }

  let entropySum = 0;
  for (const count of byteFrequency.values()) {
    const p = count / bytes.length;
    if (p > 0) {
      entropySum -= p * Math.log2(p);
    }
  }

  const maxEntropy = Math.log2(256);
  const score = entropySum / maxEntropy;
  const issues = [];

  if (score < BIP39_CONSTANTS.ENTROPY_QUALITY_THRESHOLD) {
    issues.push(`Low entropy score: ${score.toFixed(2)}`);
  }

  const allZeros = bytes.every(b => b === 0);
  const allSame = bytes.every(b => b === bytes[0]);

  if (allZeros) issues.push('All zeros detected');
  if (allSame) issues.push('All bytes identical');

  return {
    isValid: issues.length === 0,
    score,
    issues,
    recommendations: issues.length > 0 ? ['Use cryptographically secure random source'] : []
  };
}

const BIP39 = {
  generateMnemonic(options = {}) {
    let entropyBytes;

    if (options.entropy) {
      if (!Buffer.isBuffer(options.entropy)) {
        throw new Error('Custom entropy must be a Buffer');
      }
      entropyBytes = options.entropy;
    } else {
      entropyBytes = randomBytes(BIP39_CONSTANTS.ENTROPY_BITS / 8);
    }

    const qualityResult = validateEntropyQuality(entropyBytes);
    if (!qualityResult.isValid && !options.skipEntropyValidation) {
      throw new Error(`Entropy quality validation failed: ${qualityResult.issues.join(', ')}`);
    }

    const entropyHash = createHash('sha256').update(entropyBytes).digest();
    const entropyBinary = Array.from(entropyBytes)
      .map(byte => byte.toString(2).padStart(8, '0'))
      .join('');

    const checksumBinary = entropyHash[0]
      .toString(2)
      .padStart(8, '0')
      .slice(0, BIP39_CONSTANTS.CHECKSUM_BITS);

    const completeBinary = entropyBinary + checksumBinary;
    const mnemonicWords = [];

    for (let i = 0; i < BIP39_CONSTANTS.WORD_COUNT; i++) {
      const startBit = i * BIP39_CONSTANTS.BITS_PER_WORD;
      const endBit = startBit + BIP39_CONSTANTS.BITS_PER_WORD;
      const wordIndex = parseInt(completeBinary.slice(startBit, endBit), 2);

      if (wordIndex >= ENGLISH_WORDLIST.length) {
        throw new Error(`Invalid word index: ${wordIndex}`);
      }

      mnemonicWords.push(ENGLISH_WORDLIST[wordIndex]);
    }

    const mnemonic = mnemonicWords.join(' ');

    if (!this.validateChecksum(mnemonic)) {
      throw new Error('Generated mnemonic failed self-validation');
    }

    return {
      mnemonic,
      entropyQuality: qualityResult,
      generationTime: Date.now()
    };
  },

  deriveSeed(mnemonicPhrase, passphrase = '', options = {}) {
    if (!mnemonicPhrase || typeof mnemonicPhrase !== 'string') {
      throw new Error('Mnemonic phrase is required');
    }

    if (typeof passphrase !== 'string') {
      throw new Error('Passphrase must be a string');
    }

    const words = mnemonicPhrase.trim().split(/\s+/);
    if (!BIP39_CONSTANTS.VALID_WORD_COUNTS.includes(words.length)) {
      throw new Error(`Invalid mnemonic length: ${words.length} words`);
    }

    const normalizedMnemonic = normalizeUnicode(mnemonicPhrase.trim());
    const normalizedPassphrase = normalizeUnicode(passphrase);

    const iterations = options.iterations || BIP39_CONSTANTS.PBKDF2_ITERATIONS;
    const salt = BIP39_CONSTANTS.MNEMONIC_SALT_PREFIX + normalizedPassphrase;

    const seed = pbkdf2Sync(
      Buffer.from(normalizedMnemonic, 'utf8'),
      Buffer.from(salt, 'utf8'),
      iterations,
      BIP39_CONSTANTS.SEED_LENGTH_BYTES,
      'sha512'
    );

    return seed.toString('hex');
  },

  validateChecksum(mnemonicPhrase) {
    if (!mnemonicPhrase || typeof mnemonicPhrase !== 'string') {
      return false;
    }

    const words = mnemonicPhrase.trim().toLowerCase().split(/\s+/);

    if (!BIP39_CONSTANTS.VALID_WORD_COUNTS.includes(words.length)) {
      return false;
    }

    const wordIndices = [];
    for (const word of words) {
      const wordIndex = ENGLISH_WORDLIST.indexOf(word);
      if (wordIndex === -1) {
        return false;
      }
      wordIndices.push(wordIndex);
    }

    let completeBinary = '';
    for (const wordIndex of wordIndices) {
      completeBinary += wordIndex.toString(2).padStart(BIP39_CONSTANTS.BITS_PER_WORD, '0');
    }

    const totalBits = words.length * BIP39_CONSTANTS.BITS_PER_WORD;
    const entropyBits = (totalBits * 32) / 33;
    const checksumBits = totalBits - entropyBits;

    const entropyBinary = completeBinary.slice(0, entropyBits);
    const providedChecksum = completeBinary.slice(entropyBits);

    const entropyBytes = [];
    for (let i = 0; i < entropyBinary.length; i += 8) {
      const byteBinary = entropyBinary.slice(i, i + 8);
      entropyBytes.push(parseInt(byteBinary, 2));
    }

    const entropyBuffer = Buffer.from(entropyBytes);
    const entropyHash = createHash('sha256').update(entropyBuffer).digest();
    const expectedChecksum = entropyHash[0].toString(2).padStart(8, '0').slice(0, checksumBits);

    try {
      return timingSafeEqual(
        Buffer.from(providedChecksum, 'binary'),
        Buffer.from(expectedChecksum, 'binary')
      );
    } catch {
      return providedChecksum === expectedChecksum;
    }
  },

  validateMnemonic(mnemonicPhrase) {
    return this.validateChecksum(mnemonicPhrase);
  },

  mnemonicToEntropy(mnemonicPhrase) {
    if (!this.validateChecksum(mnemonicPhrase)) {
      throw new Error('Invalid mnemonic checksum');
    }

    const words = mnemonicPhrase.trim().toLowerCase().split(/\s+/);
    let completeBinary = '';

    for (const word of words) {
      const wordIndex = ENGLISH_WORDLIST.indexOf(word);
      completeBinary += wordIndex.toString(2).padStart(BIP39_CONSTANTS.BITS_PER_WORD, '0');
    }

    const totalBits = words.length * BIP39_CONSTANTS.BITS_PER_WORD;
    const entropyBits = (totalBits * 32) / 33;
    const entropyBinary = completeBinary.slice(0, entropyBits);

    const entropyBytes = [];
    for (let i = 0; i < entropyBinary.length; i += 8) {
      entropyBytes.push(parseInt(entropyBinary.slice(i, i + 8), 2));
    }

    return Buffer.from(entropyBytes);
  },

  getWordList() {
    return [...ENGLISH_WORDLIST];
  },

  getWordIndex(word) {
    return ENGLISH_WORDLIST.indexOf(word.toLowerCase());
  }
};

export { BIP39, BIP39_CONSTANTS, validateEntropyQuality };
export default BIP39;
