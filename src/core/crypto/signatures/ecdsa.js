/**
 * @fileoverview ECDSA signature implementation for Bitcoin
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { b58decode } from '../../../encoding/base58.js';
import { CRYPTO_CONSTANTS, NETWORK_VERSIONS } from '../../constants.js';

class ECDSAError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'ECDSAError';
    this.code = code;
    this.details = details;
  }
}

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

const ECDSA = {
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

  getPublicKey(privateKey, compressed = true) {
    const keyBuffer = validatePrivateKey(privateKey);
    return Buffer.from(secp256k1.getPublicKey(keyBuffer, compressed));
  },

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
