/**
 * @fileoverview BIP173/BIP350 Bech32 address encoding for Bitcoin
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { encodeSegwit, decodeSegwit, convertBits } from '../encoding/base32.js';
import rmd160 from '../core/crypto/hash/ripemd160.js';

/**
 * Bech32 human-readable part prefixes by network
 * @constant {Object.<string, string>}
 */
const BECH32_PREFIXES = {
  main: 'bc',
  test: 'tb'
};

/**
 * Compute HASH160 (SHA256 + RIPEMD160) of data
 * @param {Buffer} data - Input data to hash
 * @returns {Buffer} 20-byte HASH160 result
 */
function hash160(data) {
  const sha256 = createHash('sha256').update(data).digest();
  return rmd160(sha256);
}

/**
 * BIP173/BIP350 Bech32 address encoding utilities
 * @namespace BECH32
 * @description Provides encoding/decoding for native SegWit (bech32) and
 * Taproot (bech32m) Bitcoin addresses.
 */
const BECH32 = {
  /**
   * Encode a public key to a P2WPKH (Pay-to-Witness-Public-Key-Hash) address
   * @param {string} publicKeyHex - Compressed or uncompressed public key as hex
   * @param {string} [network='main'] - Network type ('main' or 'test')
   * @returns {string} Bech32-encoded P2WPKH address
   * @throws {Error} If public key length is invalid or network is unknown
   * @example
   * const address = BECH32.to_P2WPKH(compressedPubKeyHex, 'main');
   * // Returns: 'bc1q...'
   */
  to_P2WPKH(publicKeyHex, network = 'main') {
    const publicKey = Buffer.from(publicKeyHex, 'hex');

    if (publicKey.length !== 33 && publicKey.length !== 65) {
      throw new Error('Invalid public key length');
    }

    const prefix = BECH32_PREFIXES[network];
    if (!prefix) {
      throw new Error(`Invalid network: ${network}`);
    }

    const hash = hash160(publicKey);
    return encodeSegwit(prefix, 0, hash);
  },

  /**
   * Encode a script hash to a P2WSH (Pay-to-Witness-Script-Hash) address
   * @param {string|Buffer} scriptHash - 32-byte SHA256 hash of the witness script
   * @param {string} [network='main'] - Network type ('main' or 'test')
   * @returns {string} Bech32-encoded P2WSH address
   * @throws {Error} If hash length is not 32 bytes or network is unknown
   * @example
   * const address = BECH32.to_P2WSH(sha256Hash, 'main');
   * // Returns: 'bc1q...' (62 characters)
   */
  to_P2WSH(scriptHash, network = 'main') {
    const hash = Buffer.isBuffer(scriptHash) ? scriptHash : Buffer.from(scriptHash, 'hex');

    if (hash.length !== 32) {
      throw new Error('P2WSH requires 32-byte SHA256 hash');
    }

    const prefix = BECH32_PREFIXES[network];
    if (!prefix) {
      throw new Error(`Invalid network: ${network}`);
    }

    return encodeSegwit(prefix, 0, hash);
  },

  /**
   * Encode an x-only public key to a P2TR (Pay-to-Taproot) address
   * @param {string|Buffer} xOnlyPublicKey - 32-byte x-only public key
   * @param {string} [network='main'] - Network type ('main' or 'test')
   * @returns {string} Bech32m-encoded P2TR address
   * @throws {Error} If public key is not 32 bytes or network is unknown
   * @example
   * const address = BECH32.to_P2TR(xOnlyPubKey, 'main');
   * // Returns: 'bc1p...'
   */
  to_P2TR(xOnlyPublicKey, network = 'main') {
    const pubkey = Buffer.isBuffer(xOnlyPublicKey) ? xOnlyPublicKey : Buffer.from(xOnlyPublicKey, 'hex');

    if (pubkey.length !== 32) {
      throw new Error('Taproot requires 32-byte x-only public key');
    }

    const prefix = BECH32_PREFIXES[network];
    if (!prefix) {
      throw new Error(`Invalid network: ${network}`);
    }

    return encodeSegwit(prefix, 1, pubkey);
  },

  /**
   * Decode a Bech32/Bech32m address
   * @param {string} address - Bech32-encoded Bitcoin address
   * @returns {Object} Decoded address information
   * @returns {number} returns.version - Witness version (0-16)
   * @returns {Buffer} returns.program - Witness program
   * @returns {string} returns.network - Network type ('main' or 'test')
   * @returns {string} returns.type - Address type ('p2wpkh', 'p2wsh', 'p2tr', 'unknown')
   * @throws {Error} If address prefix is invalid
   * @example
   * const decoded = BECH32.decode('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq');
   * // Returns: { version: 0, program: Buffer, network: 'main', type: 'p2wpkh' }
   */
  decode(address) {
    let hrp, result;

    if (address.startsWith('bc1') || address.startsWith('BC1')) {
      hrp = 'bc';
    } else if (address.startsWith('tb1') || address.startsWith('TB1')) {
      hrp = 'tb';
    } else {
      throw new Error('Invalid bech32 address prefix');
    }

    result = decodeSegwit(hrp, address.toLowerCase());

    return {
      version: result.version,
      program: result.program,
      network: hrp === 'bc' ? 'main' : 'test',
      type: this.getAddressType(result.version, result.program.length)
    };
  },

  /**
   * Determine address type from witness version and program length
   * @param {number} version - Witness version (0-16)
   * @param {number} programLength - Length of witness program in bytes
   * @returns {string} Address type ('p2wpkh', 'p2wsh', 'p2tr', 'unknown')
   */
  getAddressType(version, programLength) {
    if (version === 0) {
      if (programLength === 20) return 'p2wpkh';
      if (programLength === 32) return 'p2wsh';
    }
    if (version === 1 && programLength === 32) {
      return 'p2tr';
    }
    return 'unknown';
  },

  /**
   * Validate a Bech32/Bech32m address
   * @param {string} address - Address to validate
   * @returns {boolean} True if address is valid
   * @example
   * BECH32.validate('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'); // true
   */
  validate(address) {
    try {
      this.decode(address);
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Get the Bech32 prefix for a network
   * @param {string} [network='main'] - Network type
   * @returns {string} Human-readable part prefix ('bc' or 'tb')
   */
  getPrefix(network = 'main') {
    return BECH32_PREFIXES[network] || BECH32_PREFIXES.main;
  }
};

export { BECH32, hash160, BECH32_PREFIXES };
export default BECH32;
