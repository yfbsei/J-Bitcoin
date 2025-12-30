/**
 * @fileoverview Comprehensive validation utilities for Bitcoin operations
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { CRYPTO_CONSTANTS } from '../core/constants.js';

/**
 * Custom error class for validation failures
 * @class ValidationError
 * @extends Error
 */
class ValidationError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'ValidationError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Validate a value is a Buffer with optional length check
 * @param {*} value - Value to validate
 * @param {number|null} [expectedLength=null] - Expected byte length
 * @param {string} [fieldName='value'] - Field name for error messages
 * @returns {boolean} True if valid
 * @throws {ValidationError} If validation fails
 */

function validateBuffer(value, expectedLength = null, fieldName = 'value') {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new ValidationError(
      `${fieldName} must be a Buffer or Uint8Array`,
      'INVALID_TYPE',
      { fieldName, actualType: typeof value }
    );
  }

  if (expectedLength !== null && value.length !== expectedLength) {
    throw new ValidationError(
      `${fieldName} must be ${expectedLength} bytes, got ${value.length}`,
      'INVALID_LENGTH',
      { fieldName, expected: expectedLength, actual: value.length }
    );
  }

  return true;
}

/**
 * Validate buffer length is within range
 * @param {Buffer} value - Buffer to validate
 * @param {number} minLength - Minimum length
 * @param {number} maxLength - Maximum length
 * @param {string} [fieldName='value'] - Field name
 * @returns {boolean} True if valid
 */
function validateBufferLength(value, minLength, maxLength, fieldName = 'value') {
  validateBuffer(value, null, fieldName);

  if (value.length < minLength || value.length > maxLength) {
    throw new ValidationError(
      `${fieldName} length must be between ${minLength} and ${maxLength} bytes`,
      'INVALID_LENGTH',
      { fieldName, min: minLength, max: maxLength, actual: value.length }
    );
  }

  return true;
}

/**
 * Validate number is within range
 * @param {number} value - Number to validate
 * @param {number} min - Minimum value
 * @param {number} max - Maximum value
 * @param {string} [fieldName='value'] - Field name
 * @returns {boolean} True if valid
 */
function validateNumberRange(value, min, max, fieldName = 'value') {
  if (typeof value !== 'number' || isNaN(value)) {
    throw new ValidationError(
      `${fieldName} must be a valid number`,
      'INVALID_TYPE',
      { fieldName, actualType: typeof value }
    );
  }

  if (value < min || value > max) {
    throw new ValidationError(
      `${fieldName} must be between ${min} and ${max}`,
      'OUT_OF_RANGE',
      { fieldName, min, max, actual: value }
    );
  }

  return true;
}

/**
 * Validate a hex string
 * @param {string} value - String to validate
 * @param {number|null} [expectedLength=null] - Expected length
 * @param {string} [fieldName='value'] - Field name
 * @returns {boolean} True if valid
 */
function validateHexString(value, expectedLength = null, fieldName = 'value') {
  if (typeof value !== 'string') {
    throw new ValidationError(
      `${fieldName} must be a string`,
      'INVALID_TYPE',
      { fieldName, actualType: typeof value }
    );
  }

  const hexRegex = /^[0-9a-fA-F]*$/;
  if (!hexRegex.test(value)) {
    throw new ValidationError(
      `${fieldName} must be a valid hex string`,
      'INVALID_HEX',
      { fieldName }
    );
  }

  if (expectedLength !== null && value.length !== expectedLength) {
    throw new ValidationError(
      `${fieldName} must be ${expectedLength} characters`,
      'INVALID_LENGTH',
      { fieldName, expected: expectedLength, actual: value.length }
    );
  }

  return true;
}

/**
 * Validate any Bitcoin address (auto-detects type)
 * @param {string} address - Address to validate
 * @param {string} [network='main'] - Network type
 * @returns {Object} Validation result
 */
function validateAddress(address, network = 'main') {
  if (typeof address !== 'string' || address.length === 0) {
    throw new ValidationError('Address must be a non-empty string', 'INVALID_ADDRESS');
  }

  const lowerAddr = address.toLowerCase();
  const upperAddr = address.toUpperCase();

  if (lowerAddr.startsWith('bc1') || lowerAddr.startsWith('tb1')) {
    return validateBech32Address(address, network);
  }

  if (address.startsWith('1') || address.startsWith('3') ||
    address.startsWith('m') || address.startsWith('n') || address.startsWith('2')) {
    return validateBase58Address(address, network);
  }

  throw new ValidationError('Unknown address format', 'UNKNOWN_FORMAT', { address });
}

function validateBech32Address(address, network = 'main') {
  const lowerAddr = address.toLowerCase();
  const expectedPrefix = network === 'main' ? 'bc1' : 'tb1';

  if (!lowerAddr.startsWith(expectedPrefix)) {
    throw new ValidationError(
      `Invalid prefix for ${network} network`,
      'INVALID_PREFIX',
      { expected: expectedPrefix, actual: lowerAddr.slice(0, 3) }
    );
  }

  if (address.length < 14 || address.length > 74) {
    throw new ValidationError(
      'Invalid bech32 address length',
      'INVALID_LENGTH',
      { length: address.length }
    );
  }

  return { valid: true, type: 'bech32', network };
}

function validateBase58Address(address, network = 'main') {
  const base58Regex = /^[1-9A-HJ-NP-Za-km-z]+$/;

  if (!base58Regex.test(address)) {
    throw new ValidationError('Invalid Base58 characters', 'INVALID_CHARACTERS');
  }

  if (address.length < 25 || address.length > 35) {
    throw new ValidationError(
      'Invalid Base58 address length',
      'INVALID_LENGTH',
      { length: address.length }
    );
  }

  return { valid: true, type: 'base58', network };
}

/**
 * Validate a private key
 * @param {string|Buffer} key - Private key
 * @param {string} [fieldName='private key'] - Field name
 * @returns {Object} Validation result with format
 */
function validatePrivateKey(key, fieldName = 'private key') {
  if (typeof key === 'string') {
    if (/^[0-9a-fA-F]{64}$/.test(key)) {
      return { valid: true, format: 'hex' };
    }
    if (key.startsWith('5') || key.startsWith('K') || key.startsWith('L') ||
      key.startsWith('9') || key.startsWith('c')) {
      return { valid: true, format: 'wif' };
    }
    throw new ValidationError(`Invalid ${fieldName} format`, 'INVALID_FORMAT');
  }

  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    if (key.length !== CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH) {
      throw new ValidationError(
        `${fieldName} must be ${CRYPTO_CONSTANTS.PRIVATE_KEY_LENGTH} bytes`,
        'INVALID_LENGTH'
      );
    }
    return { valid: true, format: 'buffer' };
  }

  throw new ValidationError(`${fieldName} must be string or Buffer`, 'INVALID_TYPE');
}

/**
 * Validate a public key
 * @param {string|Buffer} key - Public key
 * @param {string} [fieldName='public key'] - Field name
 * @returns {Object} Validation result with compressed flag
 */
function validatePublicKey(key, fieldName = 'public key') {
  let keyBuffer;

  if (typeof key === 'string') {
    keyBuffer = Buffer.from(key, 'hex');
  } else if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    keyBuffer = Buffer.from(key);
  } else {
    throw new ValidationError(`${fieldName} must be string or Buffer`, 'INVALID_TYPE');
  }

  if (keyBuffer.length === 33) {
    if (keyBuffer[0] !== 0x02 && keyBuffer[0] !== 0x03) {
      throw new ValidationError('Invalid compressed public key prefix', 'INVALID_PREFIX');
    }
    return { valid: true, compressed: true };
  }

  if (keyBuffer.length === 65) {
    if (keyBuffer[0] !== 0x04) {
      throw new ValidationError('Invalid uncompressed public key prefix', 'INVALID_PREFIX');
    }
    return { valid: true, compressed: false };
  }

  throw new ValidationError(
    `${fieldName} must be 33 (compressed) or 65 (uncompressed) bytes`,
    'INVALID_LENGTH'
  );
}

function validateDerivationPath(path) {
  if (typeof path !== 'string') {
    throw new ValidationError('Derivation path must be a string', 'INVALID_TYPE');
  }

  const pathRegex = /^m(\/\d+'?)*$/;
  if (!pathRegex.test(path)) {
    throw new ValidationError('Invalid derivation path format', 'INVALID_FORMAT', { path });
  }

  return { valid: true };
}

function validateNetwork(network) {
  const validNetworks = ['main', 'test', 'mainnet', 'testnet'];

  if (!validNetworks.includes(network)) {
    throw new ValidationError(
      `Invalid network: ${network}. Use 'main' or 'test'`,
      'INVALID_NETWORK'
    );
  }

  return network === 'main' || network === 'mainnet' ? 'main' : 'test';
}

function assertValid(condition, message, code = 'ASSERTION_FAILED') {
  if (!condition) {
    throw new ValidationError(message, code);
  }
  return true;
}

export {
  ValidationError,
  validateBuffer,
  validateBufferLength,
  validateNumberRange,
  validateHexString,
  validateAddress,
  validateBech32Address,
  validateBase58Address,
  validatePrivateKey,
  validatePublicKey,
  validateDerivationPath,
  validateNetwork,
  assertValid
};
