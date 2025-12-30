/**
 * @fileoverview Core constants and configuration for J-Bitcoin library
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

const CRYPTO_CONSTANTS = {
  SECP256K1_ORDER: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
  CURVE_ORDER: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
  FIELD_PRIME: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'),
  PRIVATE_KEY_LENGTH: 32,
  PUBLIC_KEY_COMPRESSED_LENGTH: 33,
  PUBLIC_KEY_UNCOMPRESSED_LENGTH: 65,
  SIGNATURE_LENGTH: 64,
  HASH160_LENGTH: 20,
  SHA256_LENGTH: 32,
  HASH256_LENGTH: 32
};

const BIP32_CONSTANTS = {
  MASTER_KEY_DEPTH: 0,
  ZERO_PARENT_FINGERPRINT: Buffer.alloc(4, 0),
  MASTER_CHILD_INDEX: 0,
  MASTER_KEY_HMAC_KEY: 'Bitcoin seed',
  MAX_DERIVATION_DEPTH: 255,
  EXTENDED_KEY_LENGTH: 78,
  MIN_SEED_BYTES: 16,
  MAX_SEED_BYTES: 64,
  HARDENED_OFFSET: 0x80000000
};

const BIP39_CONSTANTS = {
  ENTROPY_BITS: 128,
  CHECKSUM_BITS: 4,
  WORD_COUNT: 12,
  BITS_PER_WORD: 11,
  PBKDF2_ITERATIONS: 2048,
  SEED_LENGTH_BYTES: 64,
  MNEMONIC_SALT_PREFIX: 'mnemonic',
  MIN_ENTROPY_BYTES: 16,
  MAX_ENTROPY_BYTES: 64,
  VALID_WORD_COUNTS: [12, 15, 18, 21, 24]
};

const BIP44_CONSTANTS = {
  PURPOSE: 44,
  BITCOIN_COINTYPE: 0,
  TESTNET_COINTYPE: 1,
  DEFAULT_ACCOUNT: 0,
  EXTERNAL_CHAIN: 0,
  INTERNAL_CHAIN: 1
};

const NETWORK_VERSIONS = {
  main: {
    name: 'Bitcoin Mainnet',
    symbol: 'BTC',
    bech32Prefix: 'bc',
    versions: {
      EXTENDED_PUBLIC_KEY: Buffer.from([0x04, 0x88, 0xb2, 0x1e]),
      EXTENDED_PRIVATE_KEY: Buffer.from([0x04, 0x88, 0xad, 0xe4]),
      WIF_PRIVATE_KEY: 0x80,
      P2PKH_ADDRESS: 0x00,
      P2SH_ADDRESS: 0x05
    }
  },
  test: {
    name: 'Bitcoin Testnet',
    symbol: 'tBTC',
    bech32Prefix: 'tb',
    versions: {
      EXTENDED_PUBLIC_KEY: Buffer.from([0x04, 0x35, 0x87, 0xcf]),
      EXTENDED_PRIVATE_KEY: Buffer.from([0x04, 0x35, 0x83, 0x94]),
      WIF_PRIVATE_KEY: 0xef,
      P2PKH_ADDRESS: 0x6f,
      P2SH_ADDRESS: 0xc4
    }
  }
};

const ADDRESS_FORMATS = {
  LEGACY: 'legacy',
  SEGWIT: 'segwit',
  P2SH: 'p2sh',
  TAPROOT: 'taproot'
};

const BIP_PURPOSES = {
  LEGACY: 44,
  NESTED_SEGWIT: 49,
  NATIVE_SEGWIT: 84,
  TAPROOT: 86
};

const ENCODING_CONSTANTS = {
  BASE58_ALPHABET: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
  BECH32_ALPHABET: 'qpzry9x8gf2tvdw0s3jn54khce6mua7l',
  BECH32M_CONSTANT: 0x2bc830a3
};

const THRESHOLD_CONSTANTS = {
  MIN_PARTICIPANTS: 2,
  MAX_PARTICIPANTS: 20,
  MIN_THRESHOLD: 2,
  DEFAULT_THRESHOLD: 2,
  DEFAULT_PARTICIPANTS: 3
};

const TRANSACTION_CONSTANTS = {
  MAX_TRANSACTION_SIZE: 100000,
  MAX_INPUTS: 10000,
  MAX_OUTPUTS: 10000,
  MIN_OUTPUT_VALUE: 546,
  DEFAULT_SEQUENCE: 0xffffffff,
  SIGHASH_ALL: 0x01,
  SIGHASH_NONE: 0x02,
  SIGHASH_SINGLE: 0x03,
  SIGHASH_ANYONECANPAY: 0x80
};

function validateAndGetNetwork(network) {
  const normalizedNetwork = network === 'main' || network === 'mainnet' ? 'main' : 'test';
  const config = NETWORK_VERSIONS[normalizedNetwork];
  if (!config) {
    throw new Error(`Invalid network: ${network}. Use 'main' or 'test'`);
  }
  return config;
}

function generateDerivationPath(options = {}) {
  const {
    purpose = BIP_PURPOSES.NATIVE_SEGWIT,
    coinType = BIP44_CONSTANTS.BITCOIN_COINTYPE,
    account = 0,
    change = 0,
    addressIndex = 0
  } = options;
  return `m/${purpose}'/${coinType}'/${account}'/${change}/${addressIndex}`;
}

export {
  CRYPTO_CONSTANTS,
  BIP32_CONSTANTS,
  BIP39_CONSTANTS,
  BIP44_CONSTANTS,
  NETWORK_VERSIONS,
  ADDRESS_FORMATS,
  BIP_PURPOSES,
  ENCODING_CONSTANTS,
  THRESHOLD_CONSTANTS,
  TRANSACTION_CONSTANTS,
  validateAndGetNetwork,
  generateDerivationPath
};
