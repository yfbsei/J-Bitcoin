<p align="center">
  <h1 align="center">🔐 J-Bitcoin</h1>
  <p align="center">
    <strong>The Modern JavaScript Bitcoin Library</strong>
  </p>
  <p align="center">
    HD Wallets • Threshold Signatures (TSS) • Schnorr/ECDSA • Taproot • Zero Dependencies*
  </p>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/j-bitcoin"><img src="https://img.shields.io/npm/v/j-bitcoin.svg?style=flat-square&color=blue" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/j-bitcoin"><img src="https://img.shields.io/npm/dw/j-bitcoin.svg?style=flat-square&color=green" alt="npm downloads"></a>
  <a href="https://github.com/yfbsei/J-Bitcoin"><img src="https://img.shields.io/github/stars/yfbsei/J-Bitcoin?style=flat-square" alt="GitHub stars"></a>
  <a href="https://opensource.org/licenses/ISC"><img src="https://img.shields.io/badge/License-ISC-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-16%2B-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-Ready-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-api-reference">API</a> •
  <a href="https://github.com/yfbsei/J-Bitcoin/issues">Issues</a>
</p>

---

## Why J-Bitcoin?

| | J-Bitcoin | Others |
|---|:---:|:---:|
| **HD Wallets** (BIP32/39/44/49/84/86) | ✅ | ✅ |
| **Threshold Signatures (TSS)** | ✅ | ❌ |
| **Taproot (P2TR)** | ✅ | Some |
| **Schnorr Signatures (BIP340)** | ✅ | Some |
| **BIP322 Message Signing** | ✅ | ❌ |
| **TypeScript Support** | ✅ | ✅ |
| **Zero Native Dependencies*** | ✅ | ❌ |
| **Testnet Verified** | ✅ | ? |

<sub>*Only uses `@noble/curves` for cryptographic primitives</sub>

---

## ⚡ Quick Start

```bash
npm install j-bitcoin
```

### Create HD Wallet in 3 Lines

```javascript
import { CustodialWallet } from 'j-bitcoin';

const { wallet, mnemonic } = CustodialWallet.createNew('main', 128);
const address = wallet.getReceivingAddress(0, 0, 'segwit');

console.log('Backup:', mnemonic);
console.log('Address:', address.address); // bc1q...
```

### Threshold Signatures (2-of-3 TSS)

```javascript
import { NonCustodialWallet } from 'j-bitcoin';

// No single point of failure - requires 3 parties to sign
const { wallet, shares } = NonCustodialWallet.createNew('main', 3, 1);
const signature = wallet.sign(messageHash); // Distributed signing
```

---

## 🚀 Features

| Category | Features |
|----------|----------|
| **Wallets** | Custodial HD wallets, Non-custodial threshold wallets (TSS) |
| **Standards** | BIP32, BIP39, BIP44, BIP49, BIP84, BIP86, BIP173, BIP322, BIP340, BIP350 |
| **Addresses** | Legacy P2PKH (1...), P2SH-P2WPKH (3...), Native SegWit (bc1q...), Taproot (bc1p...) |
| **Signatures** | ECDSA, Schnorr (BIP340), Threshold signatures (TSS), BIP322 message signing |
| **Networks** | Bitcoin Mainnet, Testnet |

---

## 📖 Examples

<details>
<summary><strong>🔑 Custodial HD Wallet (Full Example)</strong></summary>

```javascript
import { CustodialWallet } from 'j-bitcoin';

// Generate new wallet (12-word mnemonic by default, 256 for 24-word)
const { wallet, mnemonic } = CustodialWallet.createNew('main', 128);
console.log('Backup mnemonic:', mnemonic);

// Derive addresses (account, index, type)
const legacy = wallet.getReceivingAddress(0, 0, 'legacy');         // 1...
const wrapped = wallet.getReceivingAddress(0, 0, 'wrapped-segwit'); // 3...
const segwit = wallet.getReceivingAddress(0, 0, 'segwit');         // bc1q...
const taproot = wallet.getReceivingAddress(0, 0, 'taproot');       // bc1p...

console.log('Legacy:', legacy.address);
console.log('SegWit:', segwit.address);
console.log('Taproot:', taproot.address);

// Get change address
const change = wallet.getChangeAddress(0, 0, 'segwit');

// Batch generate addresses
const addresses = wallet.getAddresses(0, 'segwit', 20);

// Restore from mnemonic
const restored = CustodialWallet.fromMnemonic('main', mnemonic);

// Export/import WIF
const wif = wallet.exportWIF(0, 0, 0, 'segwit');
const wifWallet = CustodialWallet.fromWIF(wif);
```

</details>

<details>
<summary><strong>🔐 Non-Custodial Threshold Wallet (TSS)</strong></summary>

```javascript
import { NonCustodialWallet } from 'j-bitcoin';

// Create TSS-only wallet (3 participants, threshold degree t=1)
// Signing requires 2t+1 = 3 participants
const { wallet, shares, config } = NonCustodialWallet.createNew('main', 3, 1);
console.log('TSS config:', config);

// Create HD + TSS wallet (combined mode)
const { wallet: hdWallet, mnemonic, shares: hdShares } = 
  NonCustodialWallet.createNewHD('main', 3, 1);

// Get TSS aggregate public key address
const tssAddress = wallet.getAddress('segwit');

// Get HD-derived addresses (same API as CustodialWallet)
const segwitAddr = hdWallet.getReceivingAddress(0, 0, 'segwit');

// Sign message hash with TSS
const messageHash = Buffer.alloc(32, 'test');
const signature = wallet.sign(messageHash);
const isValid = wallet.verify(messageHash, signature);

// Sign with HD-derived key
const hdSig = hdWallet.signMessageHD('Hello Bitcoin!', 0, 0, 'segwit');
```

</details>

<details>
<summary><strong>📝 BIP39 Mnemonic Operations</strong></summary>

```javascript
import { BIP39 } from 'j-bitcoin';

// Generate 12-word mnemonic (128-bit)
const { mnemonic } = BIP39.generateMnemonic(128);

// Generate 24-word mnemonic (256-bit)
const { mnemonic: mnemonic24 } = BIP39.generateMnemonic(256);

// Validate mnemonic
const isValid = BIP39.validateChecksum(mnemonic);

// Derive seed (with optional passphrase)
const seed = BIP39.deriveSeed(mnemonic, 'optional-passphrase');
```

</details>

<details>
<summary><strong>✍️ Schnorr & ECDSA Signatures</strong></summary>

```javascript
import { Schnorr, ECDSA } from 'j-bitcoin';

const privateKey = Buffer.alloc(32, 'key');
const messageHash = Buffer.alloc(32, 'msg');

// Schnorr (BIP340)
const schnorr = new Schnorr();
const schnorrSig = await schnorr.sign(privateKey, messageHash);
const schnorrPubKey = schnorr.getPublicKey(privateKey);
const isValidSchnorr = await schnorr.verify(schnorrSig.signature, messageHash, schnorrPubKey);

// ECDSA
const ecdsaSig = ECDSA.sign(privateKey, messageHash);
const ecdsaPubKey = ECDSA.getPublicKey(privateKey);
const isValidEcdsa = ECDSA.verify(ecdsaSig, messageHash, ecdsaPubKey);
```

</details>

<details>
<summary><strong>🏗️ Transaction Building</strong></summary>

```javascript
import { CustodialWallet } from 'j-bitcoin';

const wallet = CustodialWallet.fromMnemonic('main', mnemonic);

// Create transaction builder
const builder = wallet.createTransaction();

// Add inputs and outputs
builder.addInput(txid, vout, sequence);
builder.addOutput(address, amount);
builder.setFeeRate(10); // sat/vB

// Sign with wallet keys
await wallet.signTransaction(builder, [
  { account: 0, change: 0, index: 0, type: 'segwit' }
]);

// Get raw transaction hex
const rawTx = builder.build().toHex();
```

</details>

<details>
<summary><strong>📍 Bech32 Address Encoding</strong></summary>

```javascript
import { BECH32 } from 'j-bitcoin';

// Encode public key to SegWit address
const address = BECH32.to_P2WPKH(publicKeyHex, 'main');

// Encode to Taproot address  
const taprootAddr = BECH32.to_P2TR(xOnlyPubKeyHex, 'main');

// Decode address
const { program, version, type } = BECH32.decode(address);
```

</details>

---

## 📚 API Reference

### Wallet Classes

| Class | Description |
|-------|-------------|
| `CustodialWallet` | Full HD wallet with BIP32/39/44/49/84/86 support |
| `NonCustodialWallet` | Threshold (TSS) + HD hybrid wallet |

### Wallet Methods

| Method | Description |
|--------|-------------|
| `createNew(network, strength)` | Create new wallet with mnemonic |
| `fromMnemonic(network, mnemonic)` | Restore from BIP39 phrase |
| `fromWIF(wif)` | Import from WIF private key |
| `fromExtendedKey(network, xprv/xpub)` | Import from extended key |
| `getReceivingAddress(account, index, type)` | Get external address |
| `getChangeAddress(account, index, type)` | Get internal address |
| `getAddresses(account, type, count)` | Batch generate addresses |
| `signMessage(message, account, index, type)` | Sign message |
| `createTransaction()` | Create transaction builder |
| `signTransaction(builder, inputInfo)` | Sign transaction |
| `exportWIF(account, change, index, type)` | Export key as WIF |

### Cryptographic Modules

| Module | Description |
|--------|-------------|
| `BIP39` | Mnemonic generation (12-24 words), validation, seed derivation |
| `ECDSA` | Standard Bitcoin signatures with recovery |
| `Schnorr` | BIP340 Schnorr signatures |
| `BECH32` | Bech32/Bech32m address encoding (BIP173/BIP350) |
| `BIP322` | Generic message signing for all address types |
| `b58encode` / `b58decode` | Base58Check encoding |

---

## 🧪 Testnet Verified

All address types and signing algorithms have been tested on **Bitcoin Testnet4** with real transactions:

| Address Type | Custodial | Non-Custodial (TSS) |
|--------------|:---------:|:-------------------:|
| Legacy (P2PKH) | ✅ | ✅ |
| Wrapped SegWit (P2SH-P2WPKH) | ✅ | ✅ |
| Native SegWit (P2WPKH) | ✅ | ✅ |
| Taproot (P2TR) | ✅ | ✅ |

---

## 📁 Project Structure

```
src/
├── wallet/                    # Wallet implementations
│   ├── custodial.js          # HD wallet (BIP32/39/44/49/84/86)
│   └── non-custodial.js      # Threshold signature + HD wallet
├── bip/                       # BIP standards
│   ├── BIP173-BIP350.js      # Bech32/Bech32m encoding
│   ├── bip32/                # HD key derivation
│   ├── bip39/                # Mnemonic generation
│   └── bip49.js              # P2SH-P2WPKH support
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
│   ├── message-signing.js    # BIP322 message signing
│   └── script-builder.js     # Script creation
└── utils/
    ├── validation.js         # Input validation
    └── address-helpers.js    # Address utilities
```

---

## 🔒 Security

> ⚠️ **Important**: This library handles private keys and cryptographic material.

- **Never share** private keys, mnemonics, or threshold shares
- **Test on testnet** before mainnet deployment
- **Store securely** - use encrypted offline storage for mnemonics
- **Validate inputs** - always validate addresses and signatures
- **Clear sensitive data** - call `wallet.destroy()` when done

---

## 🛠️ Development

```bash
# Install dependencies
npm install

# Run tests
npm test
npm run test:coverage

# Run wallet compliance tests
node test/custodial-test.js
node test/non-custodial-test.js

# Run comprehensive feature tests (43 tests)
node test/test-all-features.js

# Run testnet testing (requires funding)
node test/testnet-test.js

# Lint and format
npm run lint
npm run format
```

---

## 📦 Dependencies

- [@noble/curves](https://github.com/paulmillr/noble-curves) - Audited secp256k1 implementation
- [bn.js](https://github.com/indutny/bn.js) - BigNum arithmetic

---

## 📄 License

ISC License - see [LICENSE](LICENSE)

---

## 🔗 Links

- [📦 npm Package](https://www.npmjs.com/package/j-bitcoin)
- [💻 GitHub Repository](https://github.com/yfbsei/J-Bitcoin)
- [🐛 Report Issues](https://github.com/yfbsei/J-Bitcoin/issues)

---

<p align="center">
  <strong>⭐ Star this repo if you find it useful!</strong>
</p>

<p align="center">
  Made with ❤️ for the Bitcoin community
</p>