/**
 * @fileoverview BIP32 child key derivation
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHmac, createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import { b58encode, b58decode } from '../../encoding/base58.js';
import rmd160 from '../../core/crypto/hash/ripemd160.js';
import {
  CRYPTO_CONSTANTS,
  BIP32_CONSTANTS,
  NETWORK_VERSIONS,
  validateAndGetNetwork
} from '../../core/constants.js';

/**
 * Offset for hardened key derivation (2^31)
 * @constant {number}
 */
const HARDENED_OFFSET = 0x80000000;

/**
 * Validate a Base58Check-encoded extended key
 * @param {string} key - Extended key to validate
 * @param {string|null} [expectedPrefix=null] - Expected key prefix
 * @returns {boolean} True if valid
 * @throws {Error} If key is invalid
 */

function validateExtendedKey(key, expectedPrefix = null) {
  if (!key || typeof key !== 'string') {
    throw new Error('Extended key must be a non-empty string');
  }

  const base58Regex = /^[1-9A-HJ-NP-Za-km-z]+$/;
  if (!base58Regex.test(key)) {
    throw new Error('Extended key contains invalid Base58 characters');
  }

  if (key.length !== 111) {
    throw new Error(`Invalid extended key length: expected 111, got ${key.length}`);
  }

  if (expectedPrefix && !key.startsWith(expectedPrefix)) {
    throw new Error(`Extended key has wrong prefix: expected ${expectedPrefix}`);
  }

  return true;
}

/**
 * Validate a BIP32 derivation path
 * @param {string} path - Derivation path (e.g., "m/44'/0'/0'/0/0")
 * @returns {boolean} True if valid
 * @throws {Error} If path format is invalid
 */
function validateDerivationPath(path) {
  if (!path || typeof path !== 'string') {
    throw new Error('Derivation path must be a non-empty string');
  }

  const pathRegex = /^m(\/\d+'?)*$/;
  if (!pathRegex.test(path)) {
    throw new Error(`Invalid derivation path format: ${path}`);
  }

  return true;
}

/**
 * Validate a derived child key against curve parameters
 * @param {BN} childKeyBN - Child key as big number
 * @returns {Buffer} 32-byte formatted key
 * @throws {Error} If key is zero or >= curve order
 */
function validateChildKey(childKeyBN) {
  const curveOrder = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, 'hex');

  if (childKeyBN.isZero()) {
    throw new Error('Invalid child key: key is zero');
  }

  if (childKeyBN.gte(curveOrder)) {
    throw new Error('Invalid child key: key >= curve order');
  }

  const formattedKey = childKeyBN.toBuffer('be', 32);

  if (formattedKey.length !== 32) {
    throw new Error(`Key serialization failed: expected 32 bytes, got ${formattedKey.length}`);
  }

  return formattedKey;
}

/**
 * Decode a Base58Check-encoded extended key
 * @param {string} extendedKey - Extended key (xprv/xpub/tprv/tpub)
 * @returns {Object} Decoded key information
 * @throws {Error} If key format is invalid
 */
function decodeExtendedKey(extendedKey) {
  validateExtendedKey(extendedKey);

  const decoded = b58decode(extendedKey);

  if (decoded.length !== BIP32_CONSTANTS.EXTENDED_KEY_LENGTH) {
    throw new Error(`Invalid decoded key length: ${decoded.length}`);
  }

  const version = decoded.slice(0, 4);
  const depth = decoded.readUInt8(4);
  const parentFingerprint = decoded.slice(5, 9);
  const childIndex = decoded.readUInt32BE(9);
  const chainCode = decoded.slice(13, 45);
  const keyData = decoded.slice(45, 78);

  let isPrivate = false;
  let network = 'main';

  if (version.equals(NETWORK_VERSIONS.main.versions.EXTENDED_PRIVATE_KEY)) {
    isPrivate = true;
    network = 'main';
  } else if (version.equals(NETWORK_VERSIONS.main.versions.EXTENDED_PUBLIC_KEY)) {
    isPrivate = false;
    network = 'main';
  } else if (version.equals(NETWORK_VERSIONS.test.versions.EXTENDED_PRIVATE_KEY)) {
    isPrivate = true;
    network = 'test';
  } else if (version.equals(NETWORK_VERSIONS.test.versions.EXTENDED_PUBLIC_KEY)) {
    isPrivate = false;
    network = 'test';
  } else {
    throw new Error('Unknown extended key version');
  }

  let privateKey = null;
  let publicKey = null;

  if (isPrivate) {
    if (keyData[0] !== 0x00) {
      throw new Error('Invalid private key padding');
    }
    privateKey = keyData.slice(1);
    publicKey = Buffer.from(secp256k1.getPublicKey(privateKey, true));
  } else {
    publicKey = keyData;
  }

  return {
    version,
    depth,
    parentFingerprint,
    childIndex,
    chainCode,
    privateKey,
    publicKey,
    isPrivate,
    network
  };
}

/**
 * Encode key information to a Base58Check extended key
 * @param {Object} keyInfo - Key information object
 * @returns {string} Base58Check-encoded extended key
 */
function encodeExtendedKey(keyInfo) {
  const networkConfig = NETWORK_VERSIONS[keyInfo.network];
  const buffer = Buffer.alloc(BIP32_CONSTANTS.EXTENDED_KEY_LENGTH);
  let offset = 0;

  const versionBytes = keyInfo.isPrivate
    ? networkConfig.versions.EXTENDED_PRIVATE_KEY
    : networkConfig.versions.EXTENDED_PUBLIC_KEY;

  versionBytes.copy(buffer, offset);
  offset += 4;

  buffer.writeUInt8(keyInfo.depth, offset);
  offset += 1;

  keyInfo.parentFingerprint.copy(buffer, offset);
  offset += 4;

  buffer.writeUInt32BE(keyInfo.childIndex, offset);
  offset += 4;

  keyInfo.chainCode.copy(buffer, offset);
  offset += 32;

  if (keyInfo.isPrivate) {
    buffer.writeUInt8(0x00, offset);
    offset += 1;
    keyInfo.privateKey.copy(buffer, offset);
  } else {
    keyInfo.publicKey.copy(buffer, offset);
  }

  return b58encode(buffer);
}

/**
 * Get the fingerprint of a public key (first 4 bytes of HASH160)
 * @param {Buffer} publicKey - Compressed public key
 * @returns {Buffer} 4-byte fingerprint
 */
function getFingerprint(publicKey) {
  const sha256Hash = createHash('sha256').update(publicKey).digest();
  const hash160 = rmd160(sha256Hash);
  return hash160.slice(0, 4);
}

/**
 * Derive a child key from a parent key
 * @param {Object} parentKeyInfo - Parent key information
 * @param {number} index - Child index (0-2147483647)
 * @param {boolean} [hardened=false] - Whether to use hardened derivation
 * @returns {Object} Child key information
 * @throws {Error} If hardened derivation attempted on public key
 */
function deriveChildKey(parentKeyInfo, index, hardened = false) {
  const actualIndex = hardened ? index + HARDENED_OFFSET : index;

  if (hardened && !parentKeyInfo.isPrivate) {
    throw new Error('Cannot derive hardened child from public key');
  }

  let data;
  if (hardened) {
    data = Buffer.concat([
      Buffer.from([0x00]),
      parentKeyInfo.privateKey,
      Buffer.alloc(4)
    ]);
    data.writeUInt32BE(actualIndex, 33);
  } else {
    data = Buffer.concat([
      parentKeyInfo.publicKey,
      Buffer.alloc(4)
    ]);
    data.writeUInt32BE(actualIndex, 33);
  }

  const hmac = createHmac('sha512', parentKeyInfo.chainCode);
  const hmacResult = hmac.update(data).digest();

  const derivedKeyMaterial = hmacResult.slice(0, 32);
  const childChainCode = hmacResult.slice(32, 64);

  let childPrivateKey = null;
  let childPublicKey = null;

  if (parentKeyInfo.isPrivate) {
    const parentKeyBN = new BN(parentKeyInfo.privateKey);
    const derivedBN = new BN(derivedKeyMaterial);
    const curveOrder = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, 'hex');

    const childKeyBN = parentKeyBN.add(derivedBN).mod(curveOrder);
    childPrivateKey = validateChildKey(childKeyBN);
    childPublicKey = Buffer.from(secp256k1.getPublicKey(childPrivateKey, true));
  } else {
    const parentPoint = secp256k1.ProjectivePoint.fromHex(parentKeyInfo.publicKey);
    const derivedPoint = secp256k1.ProjectivePoint.fromPrivateKey(derivedKeyMaterial);
    const childPoint = parentPoint.add(derivedPoint);
    childPublicKey = Buffer.from(childPoint.toRawBytes(true));
  }

  const parentFingerprint = getFingerprint(parentKeyInfo.publicKey);

  return {
    version: parentKeyInfo.version,
    depth: parentKeyInfo.depth + 1,
    parentFingerprint,
    childIndex: actualIndex,
    chainCode: childChainCode,
    privateKey: childPrivateKey,
    publicKey: childPublicKey,
    isPrivate: parentKeyInfo.isPrivate,
    network: parentKeyInfo.network
  };
}

/**
 * Derive a child key at a given path from an extended key
 * @param {string} path - BIP32 derivation path (e.g., "m/44'/0'/0'/0/0")
 * @param {string} extendedKey - Parent extended key (xprv/xpub)
 * @returns {Object} Derived key information
 * @throws {Error} If path or key is invalid
 */
function derive(path, extendedKey) {
  validateDerivationPath(path);
  validateExtendedKey(extendedKey);

  let currentKey = decodeExtendedKey(extendedKey);

  const segments = path.split('/').slice(1);

  for (const segment of segments) {
    const hardened = segment.endsWith("'");
    const indexStr = hardened ? segment.slice(0, -1) : segment;
    const index = parseInt(indexStr, 10);

    if (isNaN(index) || index < 0) {
      throw new Error(`Invalid path segment: ${segment}`);
    }

    if (currentKey.depth >= BIP32_CONSTANTS.MAX_DERIVATION_DEPTH) {
      throw new Error(`Maximum derivation depth exceeded: ${currentKey.depth}`);
    }

    currentKey = deriveChildKey(currentKey, index, hardened);
  }

  const extendedPrivateKey = currentKey.isPrivate ? encodeExtendedKey(currentKey) : null;

  const publicKeyInfo = { ...currentKey, isPrivate: false, privateKey: null };
  const extendedPublicKey = encodeExtendedKey(publicKeyInfo);

  return {
    extendedPrivateKey,
    extendedPublicKey,
    privateKey: currentKey.privateKey,
    publicKey: currentKey.publicKey,
    chainCode: currentKey.chainCode,
    depth: currentKey.depth,
    index: currentKey.childIndex,
    network: currentKey.network
  };
}

export {
  derive,
  deriveChildKey,
  decodeExtendedKey,
  encodeExtendedKey,
  validateDerivationPath,
  validateExtendedKey,
  getFingerprint,
  HARDENED_OFFSET
};

export default { derive };
