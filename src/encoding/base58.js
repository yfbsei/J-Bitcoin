/**
 * @fileoverview Base58Check encoding implementation for Bitcoin
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const CHECKSUM_LENGTH = 4;

/**
 * Double SHA256 hash for checksums
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 32-byte hash
 */
function doubleHash256(data) {
  return createHash('sha256').update(createHash('sha256').update(data).digest()).digest();
}

/**
 * Encode buffer to Base58 (without checksum)
 * @param {Buffer} buffer - Data to encode
 * @returns {string} Base58-encoded string
 * @throws {Error} If input is not a Buffer
 */
function encode(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('Input must be a Buffer');
  }

  if (buffer.length === 0) {
    return '';
  }

  let leadingZeros = 0;
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    leadingZeros++;
  }

  let num = BigInt(0);
  for (let i = leadingZeros; i < buffer.length; i++) {
    num = num * BigInt(256) + BigInt(buffer[i]);
  }

  const result = [];
  if (num === BigInt(0)) {
    result.push(BASE58_ALPHABET[0]);
  } else {
    while (num > 0) {
      const remainder = num % BigInt(58);
      num = num / BigInt(58);
      result.unshift(BASE58_ALPHABET[Number(remainder)]);
    }
  }

  return '1'.repeat(leadingZeros) + result.join('');
}

/**
 * Decode Base58 string (without checksum)
 * @param {string} str - Base58 string
 * @returns {Buffer} Decoded data
 * @throws {Error} If invalid characters found
 */
function decode(str) {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }

  if (str.length === 0) {
    return Buffer.alloc(0);
  }

  let leadingOnes = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    leadingOnes++;
  }

  let num = BigInt(0);
  for (let i = leadingOnes; i < str.length; i++) {
    const char = str[i];
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base58 character: ${char}`);
    }
    num = num * BigInt(58) + BigInt(index);
  }

  const bytes = [];
  if (num === BigInt(0)) {
    bytes.push(0);
  } else {
    while (num > 0) {
      const remainder = num % BigInt(256);
      num = num / BigInt(256);
      bytes.unshift(Number(remainder));
    }
  }

  const leadingZeros = new Array(leadingOnes).fill(0);
  return Buffer.from([...leadingZeros, ...bytes]);
}

/**
 * Encode buffer with Base58Check (with checksum)
 * @param {Buffer} buffer - Data to encode
 * @returns {string} Base58Check-encoded string
 * @throws {Error} If input invalid or checksum fails
 */
function b58encode(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('Input must be a Buffer');
  }

  const checksum = doubleHash256(buffer).slice(0, CHECKSUM_LENGTH);
  const checkedBuf = Buffer.concat([buffer, checksum]);
  const encoded = encode(checkedBuf);

  let leadingZeros = 0;
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    leadingZeros++;
  }

  let decodedLeadingOnes = 0;
  for (let i = 0; i < encoded.length && encoded[i] === '1'; i++) {
    decodedLeadingOnes++;
  }

  if (decodedLeadingOnes !== leadingZeros) {
    throw new Error(
      `Leading zero preservation failed: expected ${leadingZeros} '1' chars, got ${decodedLeadingOnes}`
    );
  }

  return encoded;
}

/**
 * Decode Base58Check string (with checksum verification)
 * @param {string} encoded - Base58Check string
 * @returns {Buffer} Decoded data (without checksum)
 * @throws {Error} If checksum verification fails
 */
function b58decode(encoded) {
  if (typeof encoded !== 'string') {
    throw new Error('Input must be a string');
  }

  const decoded = decode(encoded);

  if (decoded.length < CHECKSUM_LENGTH) {
    throw new Error('Decoded data too short for checksum verification');
  }

  const data = decoded.slice(0, -CHECKSUM_LENGTH);
  const providedChecksum = decoded.slice(-CHECKSUM_LENGTH);
  const expectedChecksum = doubleHash256(data).slice(0, CHECKSUM_LENGTH);

  if (!providedChecksum.equals(expectedChecksum)) {
    throw new Error('Checksum verification failed');
  }

  return data;
}

function encodeBase58Check(data) {
  return b58encode(data);
}

function decodeBase58Check(encoded) {
  return b58decode(encoded);
}

export { b58encode, b58decode, encode, decode, encodeBase58Check, decodeBase58Check };
export default { b58encode, b58decode, encode, decode, encodeBase58Check, decodeBase58Check };
