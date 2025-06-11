# J-Bitcoin

[![npm version](https://badge.fury.io/js/j-bitcoin.svg)](https://badge.fury.io/js/j-bitcoin)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-16%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![JSDoc](https://img.shields.io/badge/JSDoc-Complete-brightgreen.svg)](https://jsdoc.app/)

A comprehensive JavaScript/TypeScript cryptocurrency wallet library focused exclusively on Bitcoin (BTC) with both custodial and non-custodial wallet support, featuring advanced threshold signature schemes.

## 🚀 Key Features

### 💼 Wallet Technologies
- **Custodial Wallets** - HD wallets with BIP32/BIP39 support
- **Non-Custodial Wallets** - Advanced threshold signature schemes (TSS)
- **Multi-party Control** - 2-of-3, 3-of-5, and custom threshold configurations

### 🔐 Cryptographic Standards
- **BIP32** - Hierarchical Deterministic Wallets
- **BIP39** - Mnemonic Seed Phrases (12-word entropy)
- **BIP340** - Schnorr Signatures for Bitcoin
- **ECDSA** - Standard Bitcoin signatures with recovery
- **Threshold Signatures** - Distributed signature generation
- **Shamir's Secret Sharing** - Secure key distribution

### 🏠 Address Support
- **Legacy P2PKH** - Traditional Bitcoin addresses (1...)
- **SegWit Bech32** - Modern Bitcoin addresses (bc1...)
- **Network Support** - Bitcoin Mainnet & Testnet

### 📝 Developer Experience
- **Full TypeScript Support** - Complete type definitions and IntelliSense
- **Comprehensive JSDoc** - Rich inline documentation with examples
- **ES Modules** - Modern JavaScript with tree shaking support
- **Bitcoin Constants** - Built-in BIP44 paths and network configurations
- **Error Handling** - Proper Error objects with detailed messages

## 📚 Documentation

**[Complete API Documentation](https://yfbsei.github.io/J-Bitcoin/j-bitcoin/2.0.0/)**

## 📦 Installation

```bash
npm install j-bitcoin
```

**Requirements:**
- Node.js 16.0.0 or higher
- npm 7.0.0 or higher

## 🎯 Quick Start Examples

### Custodial Wallet (JavaScript)

```javascript
import { Custodial_Wallet, BIP44_CONSTANTS } from 'j-bitcoin';

// Generate new wallet with mnemonic
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
console.log('Mnemonic:', mnemonic);
console.log('Root Address:', wallet.address);

// Use convenience methods for standard Bitcoin derivation
const receivingAddr = wallet.deriveReceivingAddress(0);  // m/44'/0'/0'/0/0
const changeAddr = wallet.deriveChangeAddress(0);        // m/44'/0'/0'/1/0

console.log('First Receiving:', receivingAddr);
console.log('First Change:', changeAddr);

// Sign and verify messages
const [signature, recoveryId] = wallet.sign("Hello Bitcoin!");
const isValid = wallet.verify(signature, "Hello Bitcoin!");
console.log('Signature valid:', isValid);

// Get comprehensive wallet summary
const summary = wallet.getSummary();
console.log(`Wallet has ${summary.receivingAddresses} receiving addresses`);
```

### Custodial Wallet (TypeScript)

```typescript
import { 
  Custodial_Wallet, 
  ECDSASignatureResult, 
  WalletSummary,
  NetworkType,
  ChildKeyInfo
} from 'j-bitcoin';

// Type-safe wallet generation
const network: NetworkType = 'main';
const [mnemonic, wallet]: [string, Custodial_Wallet] = 
  Custodial_Wallet.fromRandom(network);

// Type-safe operations with full IntelliSense
const signature: ECDSASignatureResult = wallet.sign("Hello Bitcoin!");
const summary: WalletSummary = wallet.getSummary();
const receivingKeys: ChildKeyInfo[] = wallet.getChildKeysByType('receiving');

// Restore wallet with type safety
const restoredWallet: Custodial_Wallet = 
  Custodial_Wallet.fromMnemonic(network, mnemonic, 'optional-passphrase');
```

### Threshold Signatures (Advanced)

```javascript
import { Non_Custodial_Wallet } from 'j-bitcoin';

// Create 2-of-3 threshold wallet
const threshold = 2;
const participants = 3;
const walletShares = Non_Custodial_Wallet.generate_shares(threshold, participants, 'main');

// Each participant gets their share
const [share1, share2, share3] = walletShares;

// Simulate distributed signing (requires threshold participants)
const message = "Threshold signature test";
const signatures = [
  share1.sign(message),  // Participant 1 signs
  share2.sign(message)   // Participant 2 signs (threshold reached)
];

// Combine signatures
const combinedSignature = Non_Custodial_Wallet.combine_signatures(signatures, message);
console.log('Threshold signature created:', combinedSignature.serialized_sig);
```

### Schnorr Signatures (BIP340)

```javascript
import { schnorr_sig } from 'j-bitcoin';

// Generate key and sign with Schnorr
const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
const message = "Schnorr signature test";

const signature = schnorr_sig.sign(privateKey, message);
const publicKey = schnorr_sig.retrieve_public_key(privateKey);
const isValid = schnorr_sig.verify(signature, message, publicKey);

console.log('Schnorr signature valid:', isValid);
```

## 🏗️ Architecture Overview

### Core Components

```
src/
├── wallets/
│   ├── custodial/          # HD wallet implementation
│   └── non-custodial/      # Threshold signature wallets
├── core/
│   ├── crypto/             # Cryptographic primitives
│   ├── keys/               # Key management (BIP32/BIP39)
│   └── math/               # Mathematical operations
├── encoding/
│   ├── address/            # Address encoding/decoding
│   └── base58/             # Base58 encoding utilities
└── constants/              # Bitcoin network constants
```

### TypeScript Integration

Full TypeScript support with comprehensive interfaces:

```typescript
// Complete type definitions available
interface WalletSummary {
  mnemonic?: string;
  rootKey: string;
  network: NetworkType;
  receivingAddresses: number;
  changeAddresses: number;
  totalDerived: number;
  createdAt: string;
}

interface ThresholdSignatureResult {
  sig: { r: bigint; s: bigint; };
  serialized_sig: string;
  msgHash: Buffer;
  recovery_id: number;
}
```

## 📊 Feature Comparison

| Feature | Custodial | Non-Custodial | Status |
|---------|-----------|---------------|---------|
| HD Key Derivation | ✅ | ✅ | Complete |
| BIP39 Mnemonics | ✅ | ✅ | Complete |
| ECDSA Signatures | ✅ | ✅ | Complete |
| Schnorr Signatures | ✅ | ✅ | Complete |
| Threshold Signatures | ❌ | ✅ | Complete |
| Legacy Addresses | ✅ | ✅ | Complete |
| SegWit Addresses | ✅ | ✅ | Complete |
| TypeScript Support | ✅ | ✅ | Complete |
| Network Support | BTC Main/Test | BTC Main/Test | Complete |

## 🔧 Development

### Setup

```bash
# Clone repository
git clone https://github.com/yfbsei/J-Bitcoin.git
cd J-Bitcoin

# Install dependencies
npm install

# Development commands
npm run test           # Run test suite
npm run test:coverage  # Test with coverage report
npm run test:watch     # Watch mode testing
npm run lint           # Code linting
npm run lint:fix       # Auto-fix linting issues
npm run format         # Code formatting
npm run docs           # Generate documentation
npm run build          # Build project
```

### Testing

Comprehensive test suite with coverage reporting:

```bash
# Run all tests
npm test

# Generate coverage report
npm run test:coverage

# Watch for changes
npm run test:watch
```

### Documentation Generation

```bash
# Generate API documentation
npm run docs

# Serve documentation locally
npm run docs:serve  # Available at http://localhost:8080
```

## 🔒 Security Best Practices

### Key Management
- **Secure Storage**: Store mnemonic phrases in secure, offline locations
- **Share Distribution**: Use encrypted channels for threshold share distribution
- **Access Control**: Implement proper authentication for wallet operations
- **Regular Rotation**: Consider periodic key rotation for high-value wallets

### Development Guidelines
- **Input Validation**: Always validate addresses, amounts, and signatures
- **Error Handling**: Implement comprehensive error handling for all operations
- **Testing**: Thoroughly test on testnet before mainnet deployment
- **Auditing**: Maintain audit trails for all cryptographic operations

### Production Deployment
- **Environment Separation**: Isolate development and production environments
- **Monitoring**: Implement monitoring for wallet operations and security events
- **Backup Procedures**: Establish reliable backup and recovery procedures
- **Incident Response**: Have plans for handling security incidents

## 📋 API Reference

### Built-in Constants

```javascript
import { BIP44_CONSTANTS, NETWORK_CONSTANTS } from 'j-bitcoin';

// Bitcoin derivation paths
BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET;  // 0
BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET;  // 1

// Network configurations
NETWORK_CONSTANTS.BITCOIN_MAINNET.public;    // 0x0488b21e
NETWORK_CONSTANTS.BITCOIN_TESTNET.public;    // 0x043587cf
```

### Core Classes

| Class | Purpose | Key Methods |
|-------|---------|-------------|
| `Custodial_Wallet` | HD wallet management | `fromRandom()`, `fromMnemonic()`, `sign()`, `derive()` |
| `Non_Custodial_Wallet` | Threshold signatures | `generate_shares()`, `combine_signatures()`, `sign()` |
| `BIP39` | Mnemonic handling | `generate()`, `validate()`, `toSeed()`, `toEntropy()` |
| `ECDSA` | Standard signatures | `sign()`, `verify()`, `recover()` |
| `schnorr_sig` | Schnorr signatures | `sign()`, `verify()`, `retrieve_public_key()` |
| `BECH32` | Address encoding | `encode()`, `decode()`, `validate()` |

## 🔮 Roadmap

### Version 2.1 (Q3 2025)
- [ ] Enhanced error handling with custom error types
- [ ] Performance optimizations for threshold operations
- [ ] Additional address format support (P2SH, P2WSH)
- [ ] Expanded test coverage and benchmarks

### Version 2.2 (Q4 2025)
- [ ] Transaction building and broadcasting utilities
- [ ] SPV wallet implementation
- [ ] Hardware wallet integration support
- [ ] Advanced script template system

### Version 3.0 (2026)
- [ ] Lightning Network integration
- [ ] WebAssembly optimization
- [ ] React/Vue component library
- [ ] Cross-platform mobile support

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with tests
4. Run the test suite: `npm test`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to your branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Development Standards

- Follow existing code style (ESLint + Prettier configured)
- Add tests for new functionality
- Update documentation for API changes
- Ensure TypeScript compatibility

## 📜 License

ISC License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Bitcoin Core Team** - Reference implementation and standards
- **BIP Authors** - Bitcoin Improvement Proposal specifications
- **Noble Crypto** - Excellent secp256k1 cryptographic library
- **Open Source Community** - Continuous innovation and peer review

## 📞 Support & Resources

- **Issues**: [GitHub Issues](https://github.com/yfbsei/J-Bitcoin/issues)
- **Documentation**: [API Documentation](https://yfbsei.github.io/J-Bitcoin/j-bitcoin/2.0.0/)
- **Examples**: [Examples Directory](https://github.com/yfbsei/J-Bitcoin/tree/main/examples)
- **Discussions**: [GitHub Discussions](https://github.com/yfbsei/J-Bitcoin/discussions)

## ⚠️ Important Security Notice

This library handles private keys and cryptographic material. Always:

- Test thoroughly in development environments
- Use testnet for initial testing
- Implement proper key management practices
- Keep dependencies updated
- Follow security best practices for production deployments

**Never share private keys, mnemonics, or threshold shares over insecure channels.**

---

**Made with ❤️ for the Bitcoin community**