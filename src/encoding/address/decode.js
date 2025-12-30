/**
 * @fileoverview Bitcoin address and key decoding utilities
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { b58decode } from '../base58.js';
import { decodeSegwit } from '../base32.js';
import { NETWORK_VERSIONS, CRYPTO_CONSTANTS } from '../../core/constants.js';

/**
 * Custom error class for decoding operations
 * @class DecodingError
 * @extends Error
 */
class DecodingError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'DecodingError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Decode a WIF-encoded private key
 * @param {string} wif - WIF string
 * @returns {Object} Decoded {privateKey, network, compressed}
 * @throws {DecodingError} If WIF format invalid
 */

function decodeWIFPrivateKey(wif) {
  if (typeof wif !== 'string') {
    throw new DecodingError('WIF must be a string', 'INVALID_TYPE');
  }

  const decoded = b58decode(wif);

  if (decoded.length !== 33 && decoded.length !== 34) {
    throw new DecodingError(
      `Invalid WIF length: ${decoded.length}`,
      'INVALID_LENGTH'
    );
  }

  const versionByte = decoded[0];
  let network, compressed;

  if (versionByte === NETWORK_VERSIONS.main.versions.WIF_PRIVATE_KEY) {
    network = 'main';
  } else if (versionByte === NETWORK_VERSIONS.test.versions.WIF_PRIVATE_KEY) {
    network = 'test';
  } else {
    throw new DecodingError('Invalid WIF version byte', 'INVALID_VERSION');
  }

  if (decoded.length === 34) {
    if (decoded[33] !== 0x01) {
      throw new DecodingError('Invalid compression flag', 'INVALID_COMPRESSION');
    }
    compressed = true;
  } else {
    compressed = false;
  }

  const privateKey = decoded.slice(1, 33);

  return {
    privateKey,
    network,
    compressed
  };
}

/**
 * Decode a legacy (Base58Check) address
 * @param {string} address - Bitcoin address
 * @returns {Object} Decoded {hash160, network, type, version}
 * @throws {DecodingError} If address invalid
 */
function decodeLegacyAddress(address) {
  if (typeof address !== 'string') {
    throw new DecodingError('Address must be a string', 'INVALID_TYPE');
  }

  const decoded = b58decode(address);

  if (decoded.length !== 21) {
    throw new DecodingError(
      `Invalid address length: ${decoded.length}`,
      'INVALID_LENGTH'
    );
  }

  const versionByte = decoded[0];
  const hash160 = decoded.slice(1, 21);

  let network, type;

  if (versionByte === NETWORK_VERSIONS.main.versions.P2PKH_ADDRESS) {
    network = 'main';
    type = 'p2pkh';
  } else if (versionByte === NETWORK_VERSIONS.main.versions.P2SH_ADDRESS) {
    network = 'main';
    type = 'p2sh';
  } else if (versionByte === NETWORK_VERSIONS.test.versions.P2PKH_ADDRESS) {
    network = 'test';
    type = 'p2pkh';
  } else if (versionByte === NETWORK_VERSIONS.test.versions.P2SH_ADDRESS) {
    network = 'test';
    type = 'p2sh';
  } else {
    throw new DecodingError('Unknown address version', 'UNKNOWN_VERSION');
  }

  return {
    hash160,
    network,
    type,
    version: versionByte
  };
}

/**
 * Decode a SegWit (Bech32/Bech32m) address
 * @param {string} address - Bech32 address
 * @returns {Object} Decoded {program, version, network, type}
 * @throws {DecodingError} If address invalid
 */
function decodeSegwitAddress(address) {
  const lowerAddr = address.toLowerCase();
  let hrp;

  if (lowerAddr.startsWith('bc1')) {
    hrp = 'bc';
  } else if (lowerAddr.startsWith('tb1')) {
    hrp = 'tb';
  } else {
    throw new DecodingError('Invalid segwit address prefix', 'INVALID_PREFIX');
  }

  const result = decodeSegwit(hrp, lowerAddr);
  const network = hrp === 'bc' ? 'main' : 'test';

  let type;
  if (result.version === 0) {
    type = result.program.length === 20 ? 'p2wpkh' : 'p2wsh';
  } else if (result.version === 1) {
    type = 'p2tr';
  } else {
    type = `witness_v${result.version}`;
  }

  return {
    program: result.program,
    version: result.version,
    network,
    type
  };
}

/**
 * Decode any Bitcoin address (auto-detects type)
 * @param {string} address - Bitcoin address
 * @returns {Object} Decoded address information
 * @throws {DecodingError} If address invalid
 */
function decodeAddress(address) {
  if (typeof address !== 'string' || address.length === 0) {
    throw new DecodingError('Address must be a non-empty string', 'INVALID_ADDRESS');
  }

  const lowerAddr = address.toLowerCase();

  if (lowerAddr.startsWith('bc1') || lowerAddr.startsWith('tb1')) {
    return decodeSegwitAddress(address);
  }

  return decodeLegacyAddress(address);
}

/**
 * Decode an extended key (xprv/xpub/tprv/tpub)
 * @param {string} extendedKey - Extended key string
 * @returns {Object} Decoded key information
 * @throws {DecodingError} If key format invalid
 */
function decodeExtendedKey(extendedKey) {
  if (typeof extendedKey !== 'string') {
    throw new DecodingError('Extended key must be a string', 'INVALID_TYPE');
  }

  const decoded = b58decode(extendedKey);

  if (decoded.length !== 78) {
    throw new DecodingError(
      `Invalid extended key length: ${decoded.length}`,
      'INVALID_LENGTH'
    );
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
    throw new DecodingError('Unknown extended key version', 'UNKNOWN_VERSION');
  }

  let key;
  if (isPrivate) {
    if (keyData[0] !== 0x00) {
      throw new DecodingError('Invalid private key padding', 'INVALID_PADDING');
    }
    key = keyData.slice(1);
  } else {
    key = keyData;
  }

  return {
    version,
    depth,
    parentFingerprint,
    childIndex,
    chainCode,
    key,
    isPrivate,
    network
  };
}

export {
  DecodingError,
  decodeWIFPrivateKey,
  decodeLegacyAddress,
  decodeSegwitAddress,
  decodeAddress,
  decodeExtendedKey
};
