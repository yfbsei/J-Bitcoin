/**
 * @fileoverview ECDSA signature implementation for Bitcoin
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { b58decode } from '../../../encoding/base58.js';
import { CRYPTO_CONSTANTS, NETWORK_VERSIONS } from '../../constants.js';

/**
 * Custom error class for ECDSA operations
 * @class ECDSAError
 * @extends Error
 */
class ECDSAError extends Error {
  /**
   * Create an ECDSA error
   * @param {string} message - Error message
   * @param {string} code - Error code
   * @param {Object} [details={}] - Additional details
   */
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'ECDSAError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Validate a private key format and value
 * @param {string|Buffer|Uint8Array} privateKey - Private key to validate
 * @returns {Buffer} Validated 32-byte private key
 * @throws {ECDSAError} If key is invalid
 */
function validatePrivateKey(privateKey) {
  let keyBuffer;

  if (typeof privateKey === 'string') {
    if (privateKey.startsWith('5') || privateKey.startsWith('K') || privateKey.startsWith('L')) {
      keyBuffer = decodeWIFPrivateKey(privateKey);
    } else if (/^[0-9a-fA-F]{64}$/.test(privateKey)) {
      keyBuffer = Buffer.from(privateKey, 'hex');
    } else {
      throw new ECDSAError('Invalid private key format', 'INVALID_FORMAT');
    }
  } else if (Buffer.isBuffer(privateKey)) {
    keyBuffer = privateKey;
  } else if (privateKey instanceof Uint8Array) {
    keyBuffer = Buffer.from(privateKey);
  } else {
    throw new ECDSAError('Private key must be Buffer, Uint8Array, or string', 'INVALID_TYPE');
  }

  if (keyBuffer.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
    throw new ECDSAError(`Invalid private key length: ${keyBuffer.length}`, 'INVALID_LENGTH');
  }

  const keyBigInt = BigInt('0x' + keyBuffer.toString('hex'));
  const curveOrder = BigInt('0x' + CRYPTO_CONSTANTS.SECP256K1_ORDER);

  if (keyBigInt <= 0n || keyBigInt >= curveOrder) {
    throw new ECDSAError('Private key out of valid range', 'OUT_OF_RANGE');
  }

  return keyBuffer;
}

/**
 * Validate a public key format and value
 * @param {string|Buffer|Uint8Array} publicKey - Public key to validate
 * @returns {Buffer} Validated public key
 * @throws {ECDSAError} If key is invalid
 */
function validatePublicKey(publicKey) {
  let keyBuffer;

  if (typeof publicKey === 'string') {
    keyBuffer = Buffer.from(publicKey, 'hex');
  } else if (Buffer.isBuffer(publicKey)) {
    keyBuffer = publicKey;
  } else if (publicKey instanceof Uint8Array) {
    keyBuffer = Buffer.from(publicKey);
  } else {
    throw new ECDSAError('Public key must be Buffer, Uint8Array, or string', 'INVALID_TYPE');
  }

  if (keyBuffer.length !== 33 && keyBuffer.length !== 65) {
    throw new ECDSAError(`Invalid public key length: ${keyBuffer.length}`, 'INVALID_LENGTH');
  }

  try {
    secp256k1.ProjectivePoint.fromHex(keyBuffer);
  } catch {
    throw new ECDSAError('Invalid public key point', 'INVALID_POINT');
  }

  return keyBuffer;
}

/**
 * Decode a WIF-encoded private key
 * @param {string} wif - WIF-encoded private key
 * @returns {Buffer} 32-byte private key
 * @throws {ECDSAError} If WIF format is invalid
 */
function decodeWIFPrivateKey(wif) {
  const decoded = b58decode(wif);

  if (decoded.length !== 33 && decoded.length !== 34) {
    throw new ECDSAError('Invalid WIF length', 'INVALID_WIF');
  }

  const versionByte = decoded[0];
  const isMainnet = versionByte === NETWORK_VERSIONS.main.versions.WIF_PRIVATE_KEY;
  const isTestnet = versionByte === NETWORK_VERSIONS.test.versions.WIF_PRIVATE_KEY;

  if (!isMainnet && !isTestnet) {
    throw new ECDSAError('Invalid WIF version byte', 'INVALID_VERSION');
  }

  const hasCompressedFlag = decoded.length === 34;
  if (hasCompressedFlag && decoded[33] !== 0x01) {
    throw new ECDSAError('Invalid compression flag', 'INVALID_COMPRESSION');
  }

  return decoded.slice(1, 33);
}

/**
 * ECDSA signature operations for Bitcoin
 * @namespace ECDSA
 */
const ECDSA = {
  /**
   * Sign a message hash with ECDSA
   * @param {string|Buffer|Uint8Array} privateKey - Private key
   * @param {string|Buffer} messageHash - 32-byte hash to sign
   * @param {Object} [options={}] - Signing options
   * @returns {Object} Signature with r, s, recovery, signature, der
   * @throws {ECDSAError} If inputs are invalid
   */
  sign(privateKey, messageHash, options = {}) {
    const keyBuffer = validatePrivateKey(privateKey);

    let hashBuffer;
    if (typeof messageHash === 'string') {
      hashBuffer = Buffer.from(messageHash, 'hex');
    } else {
      hashBuffer = Buffer.from(messageHash);
    }

    if (hashBuffer.length !== 32) {
      throw new ECDSAError('Message hash must be 32 bytes', 'INVALID_HASH');
    }

    const signature = secp256k1.sign(hashBuffer, keyBuffer, {
      lowS: true,
      extraEntropy: options.extraEntropy
    });

    return {
      r: signature.r,
      s: signature.s,
      recovery: signature.recovery,
      signature: Buffer.from(signature.toCompactRawBytes()),
      der: Buffer.from(signature.toDERRawBytes())
    };
  },

  /**
   * Verify an ECDSA signature
   * @param {Object|Buffer|Uint8Array} signature - Signature to verify
   * @param {string|Buffer} messageHash - 32-byte message hash
   * @param {string|Buffer|Uint8Array} publicKey - Public key
   * @returns {boolean} True if signature is valid
   */
  verify(signature, messageHash, publicKey) {
    const pubKeyBuffer = validatePublicKey(publicKey);

    let hashBuffer;
    if (typeof messageHash === 'string') {
      hashBuffer = Buffer.from(messageHash, 'hex');
    } else {
      hashBuffer = Buffer.from(messageHash);
    }

    if (hashBuffer.length !== 32) {
      throw new ECDSAError('Message hash must be 32 bytes', 'INVALID_HASH');
    }

    let sigBytes;
    if (signature.r !== undefined && signature.s !== undefined) {
      const sig = new secp256k1.Signature(signature.r, signature.s);
      sigBytes = sig.toCompactRawBytes();
    } else if (Buffer.isBuffer(signature) || signature instanceof Uint8Array) {
      sigBytes = signature;
    } else {
      throw new ECDSAError('Invalid signature format', 'INVALID_SIGNATURE');
    }

    try {
      return secp256k1.verify(sigBytes, hashBuffer, pubKeyBuffer);
    } catch {
      return false;
    }
  },

  /**
   * Recover public key from signature
   * @param {Object} signature - Signature with r, s components
   * @param {string|Buffer} messageHash - Original message hash
   * @param {number} recovery - Recovery parameter (0-3)
   * @returns {Buffer} Recovered compressed public key
   * @throws {ECDSAError} If signature format is invalid
   */
  recoverPublicKey(signature, messageHash, recovery) {
    let hashBuffer;
    if (typeof messageHash === 'string') {
      hashBuffer = Buffer.from(messageHash, 'hex');
    } else {
      hashBuffer = Buffer.from(messageHash);
    }

    let sig;
    if (signature.r !== undefined && signature.s !== undefined) {
      sig = new secp256k1.Signature(signature.r, signature.s, recovery);
    } else {
      throw new ECDSAError('Invalid signature format for recovery', 'INVALID_SIGNATURE');
    }

    const recoveredPoint = sig.recoverPublicKey(hashBuffer);
    return Buffer.from(recoveredPoint.toRawBytes(true));
  },

  /**
   * Get public key from private key
   * @param {string|Buffer|Uint8Array} privateKey - Private key
   * @param {boolean} [compressed=true] - Return compressed format
   * @returns {Buffer} Public key
   */
  getPublicKey(privateKey, compressed = true) {
    const keyBuffer = validatePrivateKey(privateKey);
    return Buffer.from(secp256k1.getPublicKey(keyBuffer, compressed));
  },

  /**
   * Sign a message with Bitcoin message prefix
   * @param {string|Buffer|Uint8Array} privateKey - Private key
   * @param {string|Buffer} message - Message to sign
   * @returns {Object} Signature
   */
  signMessage(privateKey, message) {
    const messageBuffer = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
    const lengthBuffer = Buffer.from([messageBuffer.length]);

    const fullMessage = Buffer.concat([prefix, lengthBuffer, messageBuffer]);
    const messageHash = createHash('sha256')
      .update(createHash('sha256').update(fullMessage).digest())
      .digest();

    return this.sign(privateKey, messageHash);
  },

  /**
   * Verify a Bitcoin signed message
   * @param {Object} signature - Signature to verify
   * @param {string|Buffer} message - Original message
   * @param {string|Buffer|Uint8Array} publicKey - Public key
   * @returns {boolean} True if valid
   */
  verifyMessage(signature, message, publicKey) {
    const messageBuffer = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
    const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
    const lengthBuffer = Buffer.from([messageBuffer.length]);

    const fullMessage = Buffer.concat([prefix, lengthBuffer, messageBuffer]);
    const messageHash = createHash('sha256')
      .update(createHash('sha256').update(fullMessage).digest())
      .digest();

    return this.verify(signature, messageHash, publicKey);
  }
};

export {
  ECDSA,
  ECDSAError,
  validatePrivateKey,
  validatePublicKey,
  decodeWIFPrivateKey
};

export default ECDSA;
