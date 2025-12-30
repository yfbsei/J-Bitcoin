# J-Bitcoin

[![npm version](https://badge.fury.io/js/j-bitcoin.svg)](https://www.npmjs.com/package/j-bitcoin)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-16%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

A comprehensive JavaScript/TypeScript Bitcoin wallet library featuring HD wallets (BIP32/39/44/84/86), threshold signatures (nChain TSS), Schnorr/ECDSA signatures, and Taproot support.

## Features

| Category | Features |
|----------|----------|
| **Wallets** | Custodial HD wallets, Non-custodial threshold wallets (2-of-3, 3-of-5+) |
| **Standards** | BIP32, BIP39, BIP44, BIP84, BIP86, BIP173, BIP340, BIP350 |
| **Addresses** | Legacy P2PKH, SegWit P2WPKH (bc1...), Taproot P2TR (bc1p...) |
| **Signatures** | ECDSA, Schnorr (BIP340), Threshold signatures (nChain TSS) |
| **Networks** | Bitcoin Mainnet, Testnet |

## Installation

```bash
npm install j-bitcoin
```

**Requirements:** Node.js 16+ and npm 7+

## Quick Start

### Create a Custodial HD Wallet

```javascript
import { CustodialWallet } from 'j-bitcoin';

// Generate new wallet with mnemonic
const { wallet, mnemonic } = CustodialWallet.createNew('main');
console.log('Backup mnemonic:', mnemonic);

// Derive addresses
const legacyAddr = wallet.deriveLegacyAddress(0);      // P2PKH (1...)
const segwitAddr = wallet.deriveSegWitAddress(0);      // P2WPKH (bc1q...)
const taprootAddr = wallet.deriveTaprootAddress(0);    // P2TR (bc1p...)

console.log('Legacy:', legacyAddr);
console.log('SegWit:', segwitAddr);
console.log('Taproot:', taprootAddr);

// Restore from mnemonic
const restored = CustodialWallet.fromMnemonic('main', mnemonic);
```

### Create a Threshold Signature Wallet

```javascript
import { NonCustodialWallet } from 'j-bitcoin';

// Create 2-of-3 threshold wallet
const wallet = await NonCustodialWallet.create({
  threshold: 2,
  participants: 3,
  network: 'main'
});

console.log('Shared public key:', wallet.getPublicKeyHex());
console.log('SegWit address:', wallet.getSegWitAddress());

// Sign with threshold participants
const messageHash = Buffer.from('...32 byte hash...');
const signature = await wallet.sign(messageHash, [0, 1]); // Participants 0 and 1

// Verify signature
const isValid = wallet.verify(messageHash, signature);
```

### BIP39 Mnemonic Operations

```javascript
import { BIP39 } from 'j-bitcoin';

// Generate mnemonic
const { mnemonic } = BIP39.generateMnemonic();

// Validate mnemonic
const isValid = BIP39.validateChecksum(mnemonic);

// Derive seed (with optional passphrase)
const seed = BIP39.deriveSeed(mnemonic, 'optional-passphrase');
```

### Schnorr Signatures (BIP340)

```javascript
import { Schnorr } from 'j-bitcoin';

const schnorr = new Schnorr();
const privateKey = Buffer.from('...32 bytes...');
const messageHash = Buffer.from('...32 bytes...');

// Sign
const sig = await schnorr.sign(privateKey, messageHash);

// Verify
const publicKey = schnorr.getPublicKey(privateKey);
const isValid = await schnorr.verify(sig.signature, messageHash, publicKey);
```

### ECDSA Signatures

```javascript
import { ECDSA } from 'j-bitcoin';

const privateKey = '...hex or buffer...';
const messageHash = '...32 byte hex hash...';

// Sign
const sig = ECDSA.sign(privateKey, messageHash);
console.log('Signature DER:', sig.der.toString('hex'));

// Verify
const publicKey = ECDSA.getPublicKey(privateKey);
const isValid = ECDSA.verify(sig, messageHash, publicKey);
```

### Bech32 Address Encoding

```javascript
import { BECH32 } from 'j-bitcoin';

// Encode public key to SegWit address
const address = BECH32.to_P2WPKH(publicKeyHex, 'main');

// Encode to Taproot address  
const taprootAddr = BECH32.to_P2TR(xOnlyPubKeyHex, 'main');

// Decode address
const { program, version, type } = BECH32.decode(address);
```

## Project Structure

```
src/
├── wallet/                    # Wallet implementations
│   ├── custodial.js          # HD wallet (BIP32/39/44/84/86)
│   └── non-custodial.js      # Threshold signature wallet
├── bip/                       # BIP standards
│   ├── BIP173-BIP350.js      # Bech32/Bech32m encoding
│   ├── bip32/                # HD key derivation
│   └── bip39/                # Mnemonic generation
├── core/
│   ├── constants.js          # Network/crypto constants
│   ├── crypto/
│   │   ├── hash/             # RIPEMD160, HASH160
│   │   └── signatures/       # ECDSA, Schnorr, Threshold
│   └── taproot/              # Taproot support
├── encoding/
│   ├── base58.js             # Base58Check
│   ├── base32.js             # Bech32/Bech32m
│   └── address/              # Address encode/decode
├── transaction/
│   ├── builder.js            # Transaction construction
│   ├── psbt.js               # PSBT support
│   └── utxo-manager.js       # UTXO management
└── utils/
    ├── validation.js         # Input validation
    └── address-helpers.js    # Address utilities
```

## API Reference

### Wallet Classes

| Class | Description |
|-------|-------------|
| `CustodialWallet` | Full HD wallet with BIP32/39/44/84/86 support |
| `NonCustodialWallet` | Threshold signature wallet (nChain TSS protocol) |

### Cryptographic Modules

| Module | Description |
|--------|-------------|
| `BIP39` | Mnemonic generation, validation, seed derivation |
| `ECDSA` | Standard Bitcoin signatures with recovery |
| `Schnorr` | BIP340 Schnorr signatures |
| `BECH32` | Bech32/Bech32m address encoding |
| `b58encode` / `b58decode` | Base58Check encoding |

### Key Derivation

| Function | Description |
|----------|-------------|
| `generateMasterKey(seed, network)` | Generate BIP32 master key from seed |
| `derive(path, extendedKey)` | Derive child key at BIP32 path |

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test
npm run test:coverage

# Lint and format
npm run lint
npm run format

# Generate documentation
npm run docs
npm run docs:serve   # Serve at localhost:8080
```

## Security

> ⚠️ **Important**: This library handles private keys and cryptographic material.

- **Never share** private keys, mnemonics, or threshold shares
- **Test on testnet** before mainnet deployment
- **Store securely** - use encrypted offline storage for mnemonics
- **Validate inputs** - always validate addresses and signatures

## Dependencies

- [@noble/curves](https://github.com/paulmillr/noble-curves) - secp256k1 elliptic curve
- [bn.js](https://github.com/indutny/bn.js) - BigNum arithmetic

## License

ISC License - see [LICENSE](LICENSE)

## Links

- [GitHub Repository](https://github.com/yfbsei/J-Bitcoin)
- [API Documentation](https://yfbsei.github.io/J-Bitcoin)
- [npm Package](https://www.npmjs.com/package/j-bitcoin)
- [Issues](https://github.com/yfbsei/J-Bitcoin/issues)

---

**Made with ❤️ for the Bitcoin community**