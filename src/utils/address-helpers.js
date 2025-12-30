/**
 * @fileoverview Address helper functions and utilities
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { b58decode } from '../encoding/base58.js';
import { decodeSegwit } from '../encoding/base32.js';
import rmd160 from '../core/crypto/hash/ripemd160.js';
import { NETWORK_VERSIONS } from '../core/constants.js';

class AddressError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'AddressError';
    this.code = code;
    this.details = details;
  }
}

function detectAddressFormat(address) {
  if (typeof address !== 'string' || address.length === 0) {
    throw new AddressError('Address must be a non-empty string', 'INVALID_ADDRESS');
  }

  const lowerAddr = address.toLowerCase();

  if (lowerAddr.startsWith('bc1p') || lowerAddr.startsWith('tb1p')) {
    return {
      format: 'bech32m',
      type: 'p2tr',
      network: lowerAddr.startsWith('bc1') ? 'main' : 'test'
    };
  }

  if (lowerAddr.startsWith('bc1q') || lowerAddr.startsWith('tb1q')) {
    return {
      format: 'bech32',
      type: 'p2wpkh',
      network: lowerAddr.startsWith('bc1') ? 'main' : 'test'
    };
  }

  if (lowerAddr.startsWith('bc1') || lowerAddr.startsWith('tb1')) {
    return {
      format: 'bech32',
      type: 'segwit',
      network: lowerAddr.startsWith('bc1') ? 'main' : 'test'
    };
  }

  if (address.startsWith('1')) {
    return { format: 'base58', type: 'p2pkh', network: 'main' };
  }

  if (address.startsWith('3')) {
    return { format: 'base58', type: 'p2sh', network: 'main' };
  }

  if (address.startsWith('m') || address.startsWith('n')) {
    return { format: 'base58', type: 'p2pkh', network: 'test' };
  }

  if (address.startsWith('2')) {
    return { format: 'base58', type: 'p2sh', network: 'test' };
  }

  throw new AddressError('Unknown address format', 'UNKNOWN_FORMAT', { address });
}

function decodeLegacyAddress(address) {
  const decoded = b58decode(address);

  if (decoded.length !== 21) {
    throw new AddressError(
      `Invalid decoded address length: ${decoded.length}`,
      'INVALID_LENGTH'
    );
  }

  const version = decoded[0];
  const hash = decoded.slice(1, 21);

  let network, type;

  if (version === NETWORK_VERSIONS.main.versions.P2PKH_ADDRESS) {
    network = 'main';
    type = 'p2pkh';
  } else if (version === NETWORK_VERSIONS.main.versions.P2SH_ADDRESS) {
    network = 'main';
    type = 'p2sh';
  } else if (version === NETWORK_VERSIONS.test.versions.P2PKH_ADDRESS) {
    network = 'test';
    type = 'p2pkh';
  } else if (version === NETWORK_VERSIONS.test.versions.P2SH_ADDRESS) {
    network = 'test';
    type = 'p2sh';
  } else {
    throw new AddressError('Unknown address version', 'UNKNOWN_VERSION', { version });
  }

  return { version, hash, network, type };
}

function decodeAddress(address) {
  const format = detectAddressFormat(address);

  if (format.format === 'base58') {
    return decodeLegacyAddress(address);
  }

  const hrp = format.network === 'main' ? 'bc' : 'tb';
  const result = decodeSegwit(hrp, address.toLowerCase());

  return {
    version: result.version,
    program: result.program,
    network: format.network,
    type: format.type
  };
}

function hash160(data) {
  const sha256 = createHash('sha256').update(data).digest();
  return rmd160(sha256);
}

function getScriptPubKey(address) {
  const decoded = decodeAddress(address);

  if (decoded.type === 'p2pkh') {
    return Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      decoded.hash,
      Buffer.from([0x88, 0xac])
    ]);
  }

  if (decoded.type === 'p2sh') {
    return Buffer.concat([
      Buffer.from([0xa9, 0x14]),
      decoded.hash,
      Buffer.from([0x87])
    ]);
  }

  if (decoded.type === 'p2wpkh') {
    return Buffer.concat([
      Buffer.from([0x00, 0x14]),
      decoded.program
    ]);
  }

  if (decoded.type === 'p2tr') {
    return Buffer.concat([
      Buffer.from([0x51, 0x20]),
      decoded.program
    ]);
  }

  throw new AddressError('Unable to create scriptPubKey', 'UNSUPPORTED_TYPE', { type: decoded.type });
}

function isValidAddress(address, network = null) {
  try {
    const format = detectAddressFormat(address);

    if (network !== null && format.network !== network) {
      return false;
    }

    decodeAddress(address);
    return true;
  } catch {
    return false;
  }
}

const AddressSecurityUtils = {
  validateAddressChecksum(address) {
    try {
      decodeAddress(address);
      return true;
    } catch {
      return false;
    }
  },

  compareAddresses(addr1, addr2) {
    try {
      const decoded1 = decodeAddress(addr1);
      const decoded2 = decodeAddress(addr2);

      if (decoded1.type !== decoded2.type) return false;
      if (decoded1.network !== decoded2.network) return false;

      const hash1 = decoded1.hash || decoded1.program;
      const hash2 = decoded2.hash || decoded2.program;

      return hash1.equals(hash2);
    } catch {
      return false;
    }
  }
};

export {
  AddressError,
  detectAddressFormat,
  decodeLegacyAddress,
  decodeAddress,
  hash160,
  getScriptPubKey,
  isValidAddress,
  AddressSecurityUtils
};
