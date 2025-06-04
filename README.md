# J-Bitcoin

[![npm version](https://badge.fury.io/js/j-bitcoin.svg)](https://badge.fury.io/js/j-bitcoin)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-16%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![JSDoc](https://img.shields.io/badge/JSDoc-Complete-brightgreen.svg)](https://jsdoc.app/)

A comprehensive JavaScript/TypeScript cryptocurrency wallet library focused exclusively on Bitcoin (BTC) with both custodial and non-custodial wallet support.

## 🚀 Features

### 💼 Wallet Types
- **Custodial Wallets** - Traditional single-key wallets with HD derivation
- **Non-Custodial Wallets** - Advanced threshold signature schemes (TSS)

### 🔐 Cryptographic Standards
- **BIP32** - Hierarchical Deterministic Wallets
- **BIP39** - Mnemonic Seed Phrases (12-word)
- **ECDSA** - Standard Bitcoin signatures
- **Schnorr** - Modern signature scheme (BIP340)
- **Threshold Signatures** - Multi-party signature generation

### 🏠 Address Formats
- **Legacy** - P2PKH addresses (1...)
- **SegWit** - Bech32 addresses (bc1...)

### 🌐 Network Support
- Bitcoin (BTC) - Mainnet & Testnet

### 📝 Developer Experience
- **Full TypeScript Support** - Complete type definitions with IntelliSense
- **Comprehensive JSDoc** - Rich inline documentation
- **ES Modules** - Modern JavaScript module support
- **Tree Shaking** - Import only what you need
- **Bitcoin Constants** - Built-in BIP44 paths and network configurations

## 📚 Documentation

[JSDoc for J-Bitcoin](https://yfbsei.github.io/J-Bitcoin/j-bitcoin/2.0.0/)

## 📦 Installation

```bash
npm install j-bitcoin
```

## 🎯 Quick Start

### JavaScript

```javascript
import { Custodial_Wallet, BIP44_CONSTANTS } from 'j-bitcoin';

// Generate new wallet
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
console.log('Mnemonic:', mnemonic);
console.log('Address:', wallet.address);

// Use built-in convenience methods for standard Bitcoin addresses
wallet.deriveReceivingAddress(0);  // First receiving address
wallet.deriveChangeAddress(0);     // First change address

// Get wallet summary
const summary = wallet.getSummary();
console.log(`Generated ${summary.receivingAddresses} receiving addresses`);

// Sign a message
const [signature, recoveryId] = wallet.sign("Hello Bitcoin!");
console.log('Signature valid:', wallet.verify(signature, "Hello Bitcoin!"));
```

### TypeScript

```typescript
import { 
  Custodial_Wallet, 
  ECDSASignatureResult, 
  ChildKeyInfo,
  NetworkType 
} from 'j-bitcoin';

// Generate new wallet with full type safety
const network: NetworkType = 'main';
const [mnemonic, wallet]: [string, Custodial_Wallet] = 
  Custodial_Wallet.fromRandom(network);

// TypeScript knows the exact return types
const [signature, recoveryId]: ECDSASignatureResult = wallet.sign("Hello Bitcoin!");
const isValid: boolean = wallet.verify(signature, "Hello Bitcoin!");

// Full type safety for child keys
wallet.deriveReceivingAddress(0).deriveChangeAddress(0);
const childKeys: ChildKeyInfo[] = wallet.getChildKeysByType('receiving');

// IDE provides complete autocomplete and type information
console.log(childKeys[0].address);        // ✅ TypeScript knows this is a string
console.log(childKeys[0].derivationPath); // ✅ Full IntelliSense support
```

### Advanced Threshold Signatures

**JavaScript:**
```javascript
import { Non_Custodial_Wallet } from 'j-bitcoin';

// Create 2-of-3 threshold wallet
const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);

// Get shares for distribution
const shares = wallet._shares;
console.log('Distribute shares to participants:', shares);

// Generate threshold signature
const signature = wallet.sign("Multi-party transaction");
console.log('Threshold signature:', signature.serialized_sig);

// Get detailed wallet information
const summary = wallet.getSummary();
console.log(`${summary.thresholdScheme} threshold wallet - ${summary.securityLevel} security`);
```

**TypeScript:**
```typescript
import { 
  Non_Custodial_Wallet, 
  ThresholdSignatureResult,
  ThresholdWalletSummary 
} from 'j-bitcoin';

// Create 2-of-3 threshold wallet with type safety
const wallet: Non_Custodial_Wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);

// Get shares for distribution (fully typed)
const shares: string[] = wallet._shares;
console.log('Distribute shares to participants:', shares);

// Generate threshold signature (type-safe)
const signature: ThresholdSignatureResult = wallet.sign("Multi-party transaction");
console.log('Threshold signature:', signature.serialized_sig);

// Get wallet summary with complete type information
const summary: ThresholdWalletSummary = wallet.getSummary();
console.log(`${summary.thresholdScheme} - ${summary.securityLevel} security level`);
```

## 🧭 Bitcoin Constants & Utilities

### Built-in Bitcoin Standards

**JavaScript:**
```javascript
import { 
  BIP44_CONSTANTS, 
  DERIVATION_PATHS, 
  generateDerivationPath,
  BITCOIN_NETWORKS 
} from 'j-bitcoin';

// Use built-in constants for standardized operations
const wallet = Custodial_Wallet.fromRandom('main')[1];

// Generate addresses using standard paths
const receivingPath = generateDerivationPath({
  purpose: BIP44_CONSTANTS.PURPOSE,           // 44
  coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET, // 0
  account: BIP44_CONSTANTS.ACCOUNT,           // 0
  change: BIP44_CONSTANTS.CHANGE.EXTERNAL,    // 0 (receiving)
  addressIndex: 0
});

console.log(receivingPath); // "m/44'/0'/0'/0/0"
wallet.derive(receivingPath, 'pri');

// Use predefined paths
console.log(DERIVATION_PATHS.BITCOIN_FIRST_ADDRESS); // "m/44'/0'/0'/0/0"
console.log(DERIVATION_PATHS.BITCOIN_FIRST_CHANGE);  // "m/44'/0'/0'/1/0"

// Access network configurations
console.log(BITCOIN_NETWORKS.MAINNET.addressPrefix); // "bc"
console.log(BITCOIN_NETWORKS.TESTNET.addressPrefix); // "tb"
```

**TypeScript:**
```typescript
import { 
  BIP44_CONSTANTS, 
  DERIVATION_PATHS, 
  generateDerivationPath,
  DerivationPathOptions,
  ParsedDerivationPath,
  isValidBitcoinPath 
} from 'j-bitcoin';

// Type-safe derivation path generation
const pathOptions: DerivationPathOptions = {
  purpose: 44,
  coinType: 0,
  account: 0,
  change: 0,
  addressIndex: 5
};

const derivationPath: string = generateDerivationPath(pathOptions);
const isValid: boolean = isValidBitcoinPath(derivationPath);

// Parse and validate paths with full type safety
const parsedPath: ParsedDerivationPath = parseDerivationPath(derivationPath);
console.log(parsedPath.coinType);    // number (0 or 1)
console.log(parsedPath.purpose);     // number (44, 49, 84, etc.)
```

### Convenient Wallet Methods

**JavaScript:**
```javascript
const wallet = Custodial_Wallet.fromRandom('main')[1];

// Standard Bitcoin address generation
wallet.deriveReceivingAddress(0)    // m/44'/0'/0'/0/0
      .deriveReceivingAddress(1)    // m/44'/0'/0'/0/1
      .deriveChangeAddress(0)       // m/44'/0'/0'/1/0
      .deriveTestnetAddress(0);     // m/44'/1'/0'/0/0

// Filter addresses by type
const receiving = wallet.getChildKeysByType('receiving');
const change = wallet.getChildKeysByType('change');
const testnet = wallet.getChildKeysByType('testnet');

console.log(`Generated ${receiving.length} receiving addresses`);
console.log(`Generated ${change.length} change addresses`);
```

**TypeScript:**
```typescript
import { Custodial_Wallet, ChildKeyInfo, WalletSummary } from 'j-bitcoin';

const wallet: Custodial_Wallet = Custodial_Wallet.fromRandom('main')[1];

// Method chaining with full type safety
wallet.deriveReceivingAddress(0)
      .deriveReceivingAddress(1)
      .deriveChangeAddress(0)
      .deriveTestnetAddress(0);

// Type-safe address filtering
const receivingAddresses: ChildKeyInfo[] = wallet.getChildKeysByType('receiving');
const changeAddresses: ChildKeyInfo[] = wallet.getChildKeysByType('change');

// Complete wallet summary with types
const summary: WalletSummary = wallet.getSummary();
console.log(summary.network);            // string
console.log(summary.derivedKeys);        // number
console.log(summary.receivingAddresses); // number
```

### Address Conversion

**JavaScript:**
```javascript
import { BECH32 } from 'j-bitcoin';

const legacyAddress = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

// Convert to SegWit
const segwitAddr = BECH32.to_P2WPKH(legacyAddress);
console.log('SegWit:', segwitAddr);
// Output: bc1qhkfq3zahaqkkzx5mjnamwjsfpw3tvke7v6aaph

// Custom data encoding
const customAddr = BECH32.data_to_bech32("myapp", "48656c6c6f", "bech32");
console.log('Custom address:', customAddr);
```

**TypeScript:**
```typescript
import { BECH32, Bech32Encoding } from 'j-bitcoin';

const legacyAddress: string = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

// Convert to SegWit with type safety
const segwitAddr: string = BECH32.to_P2WPKH(legacyAddress);
console.log('SegWit:', segwitAddr);

// Custom encoding with proper typing
const encoding: Bech32Encoding = "bech32m";
const customAddr: string = BECH32.data_to_bech32("myapp", "deadbeef", encoding);
```

### Schnorr Signatures

**JavaScript:**
```javascript
import { schnorr_sig } from 'j-bitcoin';

const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
const message = "Hello Schnorr!";

// Sign with Schnorr
const signature = schnorr_sig.sign(privateKey, message);

// Get public key
const publicKey = schnorr_sig.retrieve_public_key(privateKey);

// Verify signature
const isValid = schnorr_sig.verify(signature, message, publicKey);
console.log('Schnorr signature valid:', isValid);
```

**TypeScript:**
```typescript
import { schnorr_sig } from 'j-bitcoin';

const privateKey: string = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
const message: string = "Hello Schnorr!";

// Sign with Schnorr (type-safe)
const signature: Uint8Array = schnorr_sig.sign(privateKey, message);

// Get public key (32-byte x-only format)
const publicKey: Uint8Array = schnorr_sig.retrieve_public_key(privateKey);

// Verify signature with full type checking
const isValid: boolean = schnorr_sig.verify(signature, message, publicKey);
console.log('Schnorr signature valid:', isValid);
```

## 📖 API Documentation

### TypeScript Support

J-Bitcoin provides complete TypeScript definitions with IntelliSense support:

```typescript
// Experience world-class developer productivity
import type { 
  Custodial_Wallet, 
  Non_Custodial_Wallet,
  ECDSASignatureResult,
  ThresholdSignatureResult,
  HDKeys,
  KeyPair,
  NetworkType,
  ChildKeyInfo,
  WalletSummary,
  ThresholdWalletSummary
} from 'j-bitcoin';

// VS Code, WebStorm, and other IDEs provide:
// ✅ Complete autocomplete for all methods
// ✅ Inline parameter documentation  
// ✅ Return type information
// ✅ Error detection at compile time
// ✅ Hover documentation for all functions

const wallet = Custodial_Wallet.fromRandom('main');
//    ^-- IDE shows: [string, Custodial_Wallet]

wallet.derive("m/44'/0'/0'/0/0", 'pri');
//     ^-- IDE shows available parameters and types

// Full interface definitions
interface ThresholdSignatureResult {
  sig: { r: bigint; s: bigint; };
  serialized_sig: string;
  msgHash: Buffer;
  recovery_id: number;
}
```

### Custodial_Wallet

| Method | Description |
|--------|-------------|
| `fromRandom(net, passphrase?)` | Generate new random wallet |
| `fromMnemonic(net, mnemonic, passphrase?)` | Import from mnemonic |
| `fromSeed(net, seed)` | Create from hex seed |
| `derive(path, keyType)` | Derive child keys |
| `deriveReceivingAddress(index)` | **New:** Standard BIP44 receiving address |
| `deriveChangeAddress(index)` | **New:** Standard BIP44 change address |
| `deriveTestnetAddress(index)` | **New:** Generate testnet address |
| `getChildKeysByType(type)` | **New:** Filter child keys by type |
| `getSummary()` | **New:** Get wallet summary information |
| `sign(message)` | Sign with ECDSA |
| `verify(sig, message)` | Verify signature |

### Non_Custodial_Wallet

| Method | Description |
|--------|-------------|
| `fromRandom(net, groupSize, threshold)` | Create threshold wallet |
| `fromShares(net, shares, threshold)` | Reconstruct from shares |
| `sign(message)` | Generate threshold signature |
| `verify(sig, msgHash)` | Verify threshold signature |
| `getSummary()` | **New:** Get threshold wallet summary |
| `_shares` | Get secret shares |
| `_privateKey` | Get reconstructed private key |

### Bitcoin Constants & Utilities

| Function | Description |
|----------|-------------|
| `generateDerivationPath(options)` | **New:** Generate BIP44 paths |
| `parseDerivationPath(path)` | **New:** Parse derivation paths |
| `isValidBitcoinPath(path)` | **New:** Validate Bitcoin paths |
| `getNetworkByCoinType(coinType)` | **New:** Get network configuration |
| `BIP44_CONSTANTS` | **New:** BIP44 constants |
| `DERIVATION_PATHS` | **New:** Standard Bitcoin paths |
| `BITCOIN_NETWORKS` | **New:** Network configurations |

### Address Utilities

| Function | Description |
|----------|-------------|
| `BECH32.to_P2WPKH(address)` | Convert to SegWit |
| `BECH32.data_to_bech32(prefix, data, encoding)` | Custom Bech32 encoding |

## 🔗 BIP32 Key Derivation

### Standard Bitcoin Paths

**JavaScript:**
```javascript
import { DERIVATION_PATHS, generateDerivationPath } from 'j-bitcoin';

// Use predefined standard paths
wallet.derive(DERIVATION_PATHS.BITCOIN_FIRST_ADDRESS);    // m/44'/0'/0'/0/0
wallet.derive(DERIVATION_PATHS.BITCOIN_FIRST_CHANGE);     // m/44'/0'/0'/1/0
wallet.derive(DERIVATION_PATHS.BITCOIN_TESTNET);          // m/44'/1'/0'

// Or use convenience methods (recommended)
wallet.deriveReceivingAddress(0);  // Same as above, more convenient
wallet.deriveChangeAddress(0);     // Same as above, more convenient
wallet.deriveTestnetAddress(0);    // Testnet address

// Generate custom paths
const customPath = generateDerivationPath({
  purpose: 44,
  coinType: 0,
  account: 1,        // Account 1
  change: 0,
  addressIndex: 10
}); // "m/44'/0'/1'/0/10"
```

**TypeScript:**
```typescript
import { 
  Custodial_Wallet, 
  KeyType, 
  DERIVATION_PATHS,
  generateDerivationPath,
  DerivationPathOptions 
} from 'j-bitcoin';

// Type-safe derivation with IntelliSense
wallet.derive(DERIVATION_PATHS.BITCOIN_FIRST_ADDRESS, 'pri' as KeyType);

// Type-safe path generation
const pathOptions: DerivationPathOptions = {
  purpose: 44,
  coinType: 0,
  account: 0,
  change: 1,        // Change addresses
  addressIndex: 5
};

const changePath: string = generateDerivationPath(pathOptions);
wallet.derive(changePath, 'pri' as KeyType);

// Convenience methods with full type safety
wallet.deriveReceivingAddress(0)  // Returns: Custodial_Wallet
      .deriveChangeAddress(0)     // Method chaining supported
      .deriveTestnetAddress(0);   // Full TypeScript support
```

## 🛡️ Security Features

- **Secure Random Generation** - Uses Node.js crypto.randomBytes()
- **Mnemonic Validation** - BIP39 checksum verification
- **Threshold Security** - Distributed key management
- **Multiple Signature Schemes** - ECDSA, Schnorr, TSS
- **Address Validation** - Built-in format checking
- **Bitcoin Standards Compliance** - Full BIP32/BIP39/BIP44 support

## 🎛️ Advanced Examples

### TypeScript Multi-Signature Escrow

**JavaScript:**
```javascript
import { Non_Custodial_Wallet } from 'j-bitcoin';

// 2-of-3 escrow: buyer, seller, arbiter
const escrow = Non_Custodial_Wallet.fromRandom("main", 3, 2);
const [buyerShare, sellerShare, arbiterShare] = escrow._shares;

// Buyer + Seller can release funds
const release = Non_Custodial_Wallet.fromShares("main", 
  [buyerShare, sellerShare], 2);

// Disputes require arbiter
const dispute = Non_Custodial_Wallet.fromShares("main",
  [buyerShare, arbiterShare], 2);

console.log('Escrow summary:', escrow.getSummary());
```

**TypeScript:**
```typescript
import { Non_Custodial_Wallet, ThresholdWalletSummary } from 'j-bitcoin';

// 2-of-3 escrow: buyer, seller, arbiter
const escrow: Non_Custodial_Wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
const [buyerShare, sellerShare, arbiterShare]: string[] = escrow._shares;

// Buyer + Seller can release funds
const release: Non_Custodial_Wallet = Non_Custodial_Wallet.fromShares("main", 
  [buyerShare, sellerShare], 2);

// Disputes require arbiter
const dispute: Non_Custodial_Wallet = Non_Custodial_Wallet.fromShares("main",
  [buyerShare, arbiterShare], 2);

const summary: ThresholdWalletSummary = escrow.getSummary();
console.log(`${summary.thresholdScheme} escrow - ${summary.securityLevel} security`);
```

### Corporate Treasury

**JavaScript:**
```javascript
import { Non_Custodial_Wallet } from 'j-bitcoin';

// 3-of-5 corporate signature
const treasury = Non_Custodial_Wallet.fromRandom("main", 5, 3);
const executiveShares = treasury._shares;

// Any 3 executives can authorize
const authorization = Non_Custodial_Wallet.fromShares("main",
  [executiveShares[0], executiveShares[2], executiveShares[4]], 3);

// Generate authorization signature
const authSignature = authorization.sign("Transfer $1M to operations");

console.log('Treasury summary:', treasury.getSummary());
console.log('Authorization signature:', authSignature.serialized_sig);
```

**TypeScript:**
```typescript
import { 
  Non_Custodial_Wallet, 
  ThresholdSignatureResult,
  ThresholdWalletSummary 
} from 'j-bitcoin';

// 3-of-5 corporate signature
const treasury: Non_Custodial_Wallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
const executiveShares: string[] = treasury._shares;

// Any 3 executives can authorize
const authorization: Non_Custodial_Wallet = Non_Custodial_Wallet.fromShares("main",
  [executiveShares[0], executiveShares[2], executiveShares[4]], 3);

// Type-safe signature generation
const authSignature: ThresholdSignatureResult = authorization.sign("Transfer $1M to operations");

const summary: ThresholdWalletSummary = treasury.getSummary();
console.log(`${summary.thresholdScheme} treasury with ${summary.securityLevel} security`);
```

### Cross-Platform Wallet with Standards

**JavaScript:**
```javascript
import { 
  Custodial_Wallet, 
  BIP44_CONSTANTS, 
  DERIVATION_PATHS 
} from 'j-bitcoin';

// Generate with passphrase using built-in constants
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main', 'secure-pass');

// Use standard Bitcoin derivation paths
wallet.deriveReceivingAddress(0)   // Standard: m/44'/0'/0'/0/0
      .deriveReceivingAddress(1)   // Standard: m/44'/0'/0'/0/1
      .deriveChangeAddress(0)      // Standard: m/44'/0'/0'/1/0
      .deriveTestnetAddress(0);    // Testnet: m/44'/1'/0'/0/0

// Get comprehensive summary
const summary = wallet.getSummary();
console.log(`Wallet on ${summary.network}`);
console.log(`${summary.receivingAddresses} receiving, ${summary.changeAddresses} change`);

// Reconstruct anywhere
const restored = Custodial_Wallet.fromMnemonic('main', mnemonic, 'secure-pass');
```

**TypeScript:**
```typescript
import { 
  Custodial_Wallet, 
  NetworkType, 
  WalletSummary,
  BIP44_CONSTANTS,
  ChildKeyInfo 
} from 'j-bitcoin';

// Type-safe network specification
const network: NetworkType = 'main';

// Generate with passphrase
const [mnemonic, wallet]: [string, Custodial_Wallet] = 
  Custodial_Wallet.fromRandom(network, 'secure-pass');

// Use convenience methods with type safety
wallet.deriveReceivingAddress(0)
      .deriveReceivingAddress(1)
      .deriveChangeAddress(0)
      .deriveTestnetAddress(0);

// Type-safe summary and filtering
const summary: WalletSummary = wallet.getSummary();
const receivingAddresses: ChildKeyInfo[] = wallet.getChildKeysByType('receiving');

console.log(`Generated ${receivingAddresses.length} receiving addresses`);

// Reconstruct with full type safety
const restored: Custodial_Wallet = 
  Custodial_Wallet.fromMnemonic(network, mnemonic, 'secure-pass');
```

## 📊 Feature Matrix

| Feature | Support | TypeScript |
|---------|---------|-------------|
| Bitcoin HD Wallets | ✅ | ✅ Full types |
| Threshold Signatures | ✅ | ✅ Complete interfaces |
| ECDSA Signatures | ✅ | ✅ Type-safe returns |
| Schnorr Signatures | ✅ | ✅ BIP340 types |
| Legacy P2PKH | ✅ | ✅ Network types |
| SegWit P2WPKH | ✅ | ✅ Bech32 types |
| **Bitcoin Constants** | ✅ | ✅ **Full integration** |
| **Convenience Methods** | ✅ | ✅ **Method chaining** |
| **Wallet Summaries** | ✅ | ✅ **Complete interfaces** |
| P2SH Addresses | ❌ | 🔄 Planned |
| P2WSH SegWit | ❌ | 🔄 Planned |
| Transaction Building | ❌ | 🔄 Planned |
| SPV Validation | ❌ | 🔄 Planned |

## 🔧 Dependencies

```json
{
  "@noble/curves": "^1.9.1",
  "base58-js": "^1.0.4", 
  "bigint-conversion": "^2.4.0",
  "bn.js": "^5.2.1"
}
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 📝 Documentation

### TypeScript IntelliSense

Experience world-class developer productivity:

```typescript
// VS Code, WebStorm, and other IDEs provide:
// ✅ Complete autocomplete for all methods
// ✅ Inline parameter documentation
// ✅ Return type information
// ✅ Error detection at compile time
// ✅ Hover documentation for Bitcoin constants

const wallet = Custodial_Wallet.fromRandom('main');
//    ^-- IDE shows: [string, Custodial_Wallet]

wallet.deriveReceivingAddress(0);
//     ^-- IDE shows method description and parameter types

// Built-in constants with IntelliSense
import { BIP44_CONSTANTS } from 'j-bitcoin';
BIP44_CONSTANTS.COIN_TYPES.
//                        ^-- IDE shows BITCOIN_MAINNET, BITCOIN_TESTNET
```

### Generate API Documentation

```bash
npm install -g jsdoc
npm run docs
```

View comprehensive documentation in `docs/index.html` with:
- **Complete API reference** with examples
- **TypeScript integration guide**
- **Bitcoin standards compliance**
- **Security best practices**
- **Advanced usage patterns**

## 🔒 Security Best Practices

### Key Management
- **Secure Backup**: Store mnemonic phrases in secure, offline locations
- **Share Distribution**: Use encrypted channels for threshold share distribution
- **Access Control**: Implement proper authentication for wallet operations
- **Regular Rotation**: Consider periodic key rotation for long-term security

### Development
- **Input Validation**: Always validate addresses and amounts before operations
- **Error Handling**: Implement comprehensive error handling for all operations
- **Testing**: Test thoroughly on testnet before mainnet deployment
- **Auditing**: Maintain audit trails for all cryptographic operations

### Production Deployment
- **Environment Separation**: Keep development and production environments isolated
- **Monitoring**: Implement monitoring for wallet operations and security events
- **Backup Procedures**: Establish reliable backup and recovery procedures
- **Incident Response**: Have plans for handling security incidents

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Setup

```bash
# Clone and install dependencies
git clone https://github.com/yfbsei/J-Bitcoin.git
cd J-Bitcoin
npm install

# Run development commands
npm run lint          # Check code style
npm run format        # Format code
npm run test          # Run tests
npm run docs          # Generate documentation
```

## 📜 License

ISC License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **BIP Authors** - For Bitcoin Improvement Proposals
- **Bitcoin Core** - Reference implementation
- **Noble Crypto** - Excellent secp256k1 library
- **Bitcoin Community** - Continuous innovation

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yfbsei/J-Bitcoin/issues)
- **Documentation**: [API Docs](https://github.com/yfbsei/J-Bitcoin/docs)
- **Examples**: [Examples Directory](https://github.com/yfbsei/J-Bitcoin/examples)

## 🔮 Roadmap

### Short Term (Q2 2025)
- [ ] P2SH and P2WSH address support with TypeScript definitions
- [ ] Enhanced error handling and validation
- [ ] Performance optimizations for threshold operations
- [ ] Additional test coverage for edge cases

### Medium Term (Q3-Q4 2025)
- [ ] Transaction building and broadcasting with type-safe interfaces
- [ ] SPV wallet implementation with comprehensive types
- [ ] Hardware wallet integration with device-specific types
- [ ] Advanced script templates with template types

### Long Term (2026+)
- [ ] Lightning Network support with protocol types
- [ ] React/Vue component library with prop types
- [ ] WebAssembly optimization with typed bindings
- [ ] Cross-chain interoperability features

## 🏆 Why Choose J-Bitcoin?

### For Developers
- **TypeScript First**: Built with TypeScript developers in mind
- **Modern Architecture**: ES modules, tree shaking, and modern JavaScript
- **Comprehensive Documentation**: Every function documented with examples
- **Developer Experience**: IntelliSense, autocomplete, and type safety
- **Bitcoin Standards**: Built-in constants and utilities for Bitcoin development

### For Enterprises
- **Threshold Security**: Advanced multi-party control for corporate treasuries
- **Compliance Ready**: Audit trails and multi-signature requirements
- **Battle Tested**: Based on proven cryptographic standards
- **Professional Support**: Enterprise-grade reliability and support

### For Researchers
- **Academic Standards**: Implements latest cryptographic research
- **Extensible Design**: Easy to extend with new algorithms
- **Reference Implementation**: Well-documented algorithms for study
- **Open Source**: Transparent implementation for peer review

---

**⚠️ Security Notice**: This library handles private keys and should be used with appropriate security measures. Always verify implementations in test environments before production use.

**Built with ❤️ for the Bitcoin ecosystem and TypeScript developers**