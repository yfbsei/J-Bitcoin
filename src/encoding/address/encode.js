/**
 * @fileoverview Bitcoin address and key encoding utilities
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { b58encode } from '../base58.js';
import rmd160 from '../../core/crypto/hash/ripemd160.js';
import { NETWORK_VERSIONS, CRYPTO_CONSTANTS } from '../../core/constants.js';

/**
 * Custom error class for encoding operations
 * @class EncodingError
 * @extends Error
 */
class EncodingError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'EncodingError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Compute HASH160 of data
 * @param {Buffer} data - Input data
 * @returns {Buffer} 20-byte hash
 */

function hash160(data) {
  const sha256 = createHash('sha256').update(data).digest();
  return rmd160(sha256);
}

/**
 * Encode a version byte and hash to Base58Check address
 * @param {number} versionByte - Network version byte
 * @param {Buffer} hash160Data - 20-byte hash
 * @returns {string} Base58Check address
 */
function encodeAddress(versionByte, hash160Data) {
  if (!Buffer.isBuffer(hash160Data) && !(hash160Data instanceof Uint8Array)) {
    throw new EncodingError('Hash160 data must be a Buffer', 'INVALID_TYPE');
  }

  if (hash160Data.length !== CRYPTO_CONSTANTS.HASH160_LENGTH) {
    throw new EncodingError(
      `Hash160 must be ${CRYPTO_CONSTANTS.HASH160_LENGTH} bytes`,
      'INVALID_LENGTH'
    );
  }

  const payload = Buffer.concat([
    Buffer.from([versionByte]),
    Buffer.from(hash160Data)
  ]);

  return b58encode(payload);
}

/**
 * Encode public key to P2PKH (legacy) address
 * @param {Buffer|string} publicKey - Compressed/uncompressed public key
 * @param {string} [network='main'] - Network type
 * @returns {string} Base58Check P2PKH address
 */
function encodeP2PKH(publicKey, network = 'main') {
  const pubKeyBuffer = Buffer.isBuffer(publicKey)
    ? publicKey
    : Buffer.from(publicKey, 'hex');

  if (pubKeyBuffer.length !== 33 && pubKeyBuffer.length !== 65) {
    throw new EncodingError('Invalid public key length', 'INVALID_LENGTH');
  }

  const hash = hash160(pubKeyBuffer);
  const versionByte = network === 'main'
    ? NETWORK_VERSIONS.main.versions.P2PKH_ADDRESS
    : NETWORK_VERSIONS.test.versions.P2PKH_ADDRESS;

  return encodeAddress(versionByte, hash);
}

/**
 * Encode script hash to P2SH address
 * @param {Buffer|string} scriptHash - 20-byte script hash
 * @param {string} [network='main'] - Network type
 * @returns {string} Base58Check P2SH address
 */
function encodeP2SH(scriptHash, network = 'main') {
  const hashBuffer = Buffer.isBuffer(scriptHash)
    ? scriptHash
    : Buffer.from(scriptHash, 'hex');

  if (hashBuffer.length !== CRYPTO_CONSTANTS.HASH160_LENGTH) {
    throw new EncodingError('Script hash must be 20 bytes', 'INVALID_LENGTH');
  }

  const versionByte = network === 'main'
    ? NETWORK_VERSIONS.main.versions.P2SH_ADDRESS
    : NETWORK_VERSIONS.test.versions.P2SH_ADDRESS;

  return encodeAddress(versionByte, hashBuffer);
}

/**
 * Encode private key to WIF format
 * @param {Buffer|string} privateKey - 32-byte private key
 * @param {string} [network='main'] - Network type
 * @param {boolean} [compressed=true] - Use compressed format
 * @returns {string} WIF-encoded private key
 */
function encodeWIF(privateKey, network = 'main', compressed = true) {
  const keyBuffer = Buffer.isBuffer(privateKey)
    ? privateKey
    : Buffer.from(privateKey, 'hex');

  if (keyBuffer.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
    throw new EncodingError(
      `Private key must be ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH} bytes`,
      'INVALID_LENGTH'
    );
  }

  const versionByte = network === 'main'
    ? NETWORK_VERSIONS.main.versions.WIF_PRIVATE_KEY
    : NETWORK_VERSIONS.test.versions.WIF_PRIVATE_KEY;

  let payload;
  if (compressed) {
    payload = Buffer.concat([
      Buffer.from([versionByte]),
      keyBuffer,
      Buffer.from([0x01])
    ]);
  } else {
    payload = Buffer.concat([
      Buffer.from([versionByte]),
      keyBuffer
    ]);
  }

  return b58encode(payload);
}

function publicKeyToHash160(publicKey) {
  const pubKeyBuffer = Buffer.isBuffer(publicKey)
    ? publicKey
    : Buffer.from(publicKey, 'hex');

  return hash160(pubKeyBuffer);
}

function scriptToHash160(script) {
  const scriptBuffer = Buffer.isBuffer(script)
    ? script
    : Buffer.from(script, 'hex');

  return hash160(scriptBuffer);
}

function scriptToSHA256(script) {
  const scriptBuffer = Buffer.isBuffer(script)
    ? script
    : Buffer.from(script, 'hex');

  return createHash('sha256').update(scriptBuffer).digest();
}

export {
  EncodingError,
  hash160,
  encodeAddress,
  encodeP2PKH,
  encodeP2SH,
  encodeWIF,
  publicKeyToHash160,
  scriptToHash160,
  scriptToSHA256
};
