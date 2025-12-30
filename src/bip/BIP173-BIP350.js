/**
 * @fileoverview BIP173/BIP350 Bech32 address encoding for Bitcoin
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import { encodeSegwit, decodeSegwit, convertBits } from '../encoding/base32.js';
import rmd160 from '../core/crypto/hash/ripemd160.js';

const BECH32_PREFIXES = {
  main: 'bc',
  test: 'tb'
};

function hash160(data) {
  const sha256 = createHash('sha256').update(data).digest();
  return rmd160(sha256);
}

const BECH32 = {
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

  validate(address) {
    try {
      this.decode(address);
      return true;
    } catch {
      return false;
    }
  },

  getPrefix(network = 'main') {
    return BECH32_PREFIXES[network] || BECH32_PREFIXES.main;
  }
};

export { BECH32, hash160, BECH32_PREFIXES };
export default BECH32;
