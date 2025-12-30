/**
 * @fileoverview Schnorr signature implementation following BIP340
 * @version 2.2.0
 * @author yfbsei
 * @license ISC
 */

import { createHash, randomBytes } from 'node:crypto';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { CRYPTO_CONSTANTS } from '../../constants.js';
import BN from 'bn.js';

class SchnorrError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'SchnorrError';
    this.code = code;
    this.details = details;
  }
}

const BIP340_CONSTANTS = {
  SIGNATURE_LENGTH: 64,
  PUBLIC_KEY_LENGTH: 32,
  PRIVATE_KEY_LENGTH: 32,
  CHALLENGE_TAG: 'BIP0340/challenge',
  AUX_TAG: 'BIP0340/aux',
  NONCE_TAG: 'BIP0340/nonce'
};

const TAPROOT_CONSTANTS = {
  LEAF_VERSION: 0xc0,
  ANNEX_TAG: 0x50,
  SIGHASH_DEFAULT: 0x00,
  SIGHASH_ALL: 0x01,
  SIGHASH_NONE: 0x02,
  SIGHASH_SINGLE: 0x03,
  SIGHASH_ANYONECANPAY: 0x80
};

const CURVE_ORDER = BigInt('0x' + CRYPTO_CONSTANTS.SECP256K1_ORDER);
const FIELD_PRIME = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');

class TaggedHash {
  static create(tag, data) {
    const tagHash = createHash('sha256').update(tag).digest();
    const taggedData = Buffer.concat([tagHash, tagHash, data]);
    return createHash('sha256').update(taggedData).digest();
  }

  static challenge(rx, publicKey, message) {
    const data = Buffer.concat([rx, publicKey, message]);
    return this.create(BIP340_CONSTANTS.CHALLENGE_TAG, data);
  }

  static auxiliary(auxRand) {
    return this.create(BIP340_CONSTANTS.AUX_TAG, auxRand);
  }

  static nonce(maskedKey, publicKey, message) {
    const data = Buffer.concat([maskedKey, publicKey, message]);
    return this.create(BIP340_CONSTANTS.NONCE_TAG, data);
  }
}

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return result;
}

function modSqrt(n, p) {
  if (p % 4n === 3n) {
    return modPow(n, (p + 1n) / 4n, p);
  }
  throw new SchnorrError('Complex modular sqrt not implemented', 'SQRT_NOT_IMPLEMENTED');
}

function liftX(xCoord) {
  const x = typeof xCoord === 'bigint' ? xCoord : BigInt('0x' + Buffer.from(xCoord).toString('hex'));

  if (x >= FIELD_PRIME) {
    throw new SchnorrError('x coordinate >= field prime', 'INVALID_X_COORD');
  }

  const ySq = (modPow(x, 3n, FIELD_PRIME) + 7n) % FIELD_PRIME;
  const y = modSqrt(ySq, FIELD_PRIME);

  if ((y * y) % FIELD_PRIME !== ySq) {
    throw new SchnorrError('No valid y coordinate exists', 'NO_Y_COORD');
  }

  const evenY = y % 2n === 0n ? y : FIELD_PRIME - y;

  return {
    x,
    y: evenY,
    toBuffer() {
      const xBuf = Buffer.alloc(32);
      const yBuf = Buffer.alloc(32);
      const xHex = x.toString(16).padStart(64, '0');
      const yHex = evenY.toString(16).padStart(64, '0');
      Buffer.from(xHex, 'hex').copy(xBuf);
      Buffer.from(yHex, 'hex').copy(yBuf);
      return { x: xBuf, y: yBuf };
    }
  };
}

function validatePrivateKey(privateKey) {
  let keyBuffer;

  if (typeof privateKey === 'string') {
    keyBuffer = Buffer.from(privateKey, 'hex');
  } else if (Buffer.isBuffer(privateKey)) {
    keyBuffer = privateKey;
  } else if (privateKey instanceof Uint8Array) {
    keyBuffer = Buffer.from(privateKey);
  } else {
    throw new SchnorrError('Private key must be Buffer or hex string', 'INVALID_TYPE');
  }

  if (keyBuffer.length !== BIP340_CONSTANTS.PRIVATE_KEY_LENGTH) {
    throw new SchnorrError(`Invalid private key length: ${keyBuffer.length}`, 'INVALID_LENGTH');
  }

  const keyBigInt = BigInt('0x' + keyBuffer.toString('hex'));
  if (keyBigInt <= 0n || keyBigInt >= CURVE_ORDER) {
    throw new SchnorrError('Private key out of valid range', 'OUT_OF_RANGE');
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
    throw new SchnorrError('Public key must be Buffer or hex string', 'INVALID_TYPE');
  }

  if (keyBuffer.length !== BIP340_CONSTANTS.PUBLIC_KEY_LENGTH) {
    throw new SchnorrError(`Invalid x-only public key length: ${keyBuffer.length}`, 'INVALID_LENGTH');
  }

  return keyBuffer;
}

function validateSignature(signature) {
  let sigBuffer;

  if (typeof signature === 'string') {
    sigBuffer = Buffer.from(signature, 'hex');
  } else if (Buffer.isBuffer(signature)) {
    sigBuffer = signature;
  } else if (signature instanceof Uint8Array) {
    sigBuffer = Buffer.from(signature);
  } else {
    throw new SchnorrError('Signature must be Buffer or hex string', 'INVALID_TYPE');
  }

  if (sigBuffer.length !== BIP340_CONSTANTS.SIGNATURE_LENGTH) {
    throw new SchnorrError(`Invalid signature length: ${sigBuffer.length}`, 'INVALID_LENGTH');
  }

  return sigBuffer;
}

class Schnorr {
  constructor() {
    this.taggedHash = TaggedHash;
  }

  async sign(privateKey, message, auxRand = null) {
    const keyBuffer = validatePrivateKey(privateKey);

    let messageBuffer;
    if (typeof message === 'string') {
      messageBuffer = Buffer.from(message, 'hex');
    } else {
      messageBuffer = Buffer.from(message);
    }

    if (messageBuffer.length !== 32) {
      throw new SchnorrError('Message must be 32 bytes', 'INVALID_MESSAGE');
    }

    const aux = auxRand || randomBytes(32);
    const signature = schnorr.sign(messageBuffer, keyBuffer, aux);

    return {
      signature: Buffer.from(signature),
      r: Buffer.from(signature.slice(0, 32)),
      s: Buffer.from(signature.slice(32, 64)),
      messageHash: messageBuffer
    };
  }

  async verify(signature, message, publicKey) {
    const sigBuffer = validateSignature(signature);
    const pubKeyBuffer = validatePublicKey(publicKey);

    let messageBuffer;
    if (typeof message === 'string') {
      messageBuffer = Buffer.from(message, 'hex');
    } else {
      messageBuffer = Buffer.from(message);
    }

    if (messageBuffer.length !== 32) {
      throw new SchnorrError('Message must be 32 bytes', 'INVALID_MESSAGE');
    }

    try {
      return schnorr.verify(sigBuffer, messageBuffer, pubKeyBuffer);
    } catch {
      return false;
    }
  }

  async getPublicKey(privateKey) {
    const keyBuffer = validatePrivateKey(privateKey);
    return Buffer.from(schnorr.getPublicKey(keyBuffer));
  }

  async tweakPrivateKey(privateKey, tweak) {
    const keyBuffer = validatePrivateKey(privateKey);

    if (!Buffer.isBuffer(tweak) || tweak.length !== 32) {
      throw new SchnorrError('Tweak must be 32 bytes', 'INVALID_TWEAK');
    }

    const publicKey = await this.getPublicKey(keyBuffer);
    const privateKeyBN = new BN(keyBuffer);
    const tweakBN = new BN(tweak);
    const curveOrderBN = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, 'hex');

    const tweakedPrivateKey = privateKeyBN.add(tweakBN).umod(curveOrderBN);

    return {
      tweakedPrivateKey: tweakedPrivateKey.toBuffer('be', 32),
      tweak: Buffer.from(tweak),
      outputPublicKey: publicKey
    };
  }

  async signTransaction(privateKey, transaction, inputIndex, prevouts, sighashType = TAPROOT_CONSTANTS.SIGHASH_DEFAULT) {
    const signature = await this.sign(privateKey, transaction);

    if (sighashType !== TAPROOT_CONSTANTS.SIGHASH_DEFAULT) {
      return Buffer.concat([signature.signature, Buffer.from([sighashType])]);
    }

    return signature.signature;
  }
}

const EnhancedSchnorr = Schnorr;

export {
  Schnorr,
  EnhancedSchnorr,
  SchnorrError,
  TaggedHash,
  BIP340_CONSTANTS,
  TAPROOT_CONSTANTS,
  liftX,
  validatePrivateKey,
  validatePublicKey,
  validateSignature
};

export default Schnorr;
