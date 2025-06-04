# J-Bitcoin

[![npm version](https://badge.fury.io/js/j-bitcoin.svg)](https://badge.fury.io/js/j-bitcoin)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![JSDoc](https://img.shields.io/badge/JSDoc-Complete-brightgreen.svg)](https://jsdoc.app/)

A comprehensive JavaScript/TypeScript cryptocurrency wallet library supporting both custodial and non-custodial wallets for Bitcoin (BTC), Bitcoin Cash (BCH), and Bitcoin SV (BSV).

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
- **CashAddr** - Bitcoin Cash format

### 🌐 Network Support
- Bitcoin (BTC) - Mainnet & Testnet
- Bitcoin Cash (BCH) - Mainnet & Testnet  
- Bitcoin SV (BSV) - Mainnet & Testnet

### 📝 Developer Experience
- **Full TypeScript Support** - Complete type definitions with IntelliSense
- **Comprehensive JSDoc** - Rich inline documentation
- **ES Modules** - Modern JavaScript module support
- **Tree Shaking** - Import only what you need

## 📦 Installation

```bash
npm install j-bitcoin
```

## 🎯 Quick Start

### JavaScript

```javascript
import { Custodial_Wallet } from 'j-bitcoin';

// Generate new wallet
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
console.log('Mnemonic:', mnemonic);
console.log('Address:', wallet.address);

// Sign a message
const [signature, recoveryId] = wallet.sign("Hello Bitcoin!");
console.log('Signature valid:', wallet.verify(signature, "Hello Bitcoin!"));
```

### TypeScript

```typescript
import { Custodial_Wallet, ECDSASignatureResult } from 'j-bitcoin';

// Generate new wallet with full type safety
const [mnemonic, wallet]: [string, Custodial_Wallet] = Custodial_Wallet.fromRandom('main');

// TypeScript knows the exact return types
const [signature, recoveryId]: ECDSASignatureResult = wallet.sign("Hello Bitcoin!");
const isValid: boolean = wallet.verify(signature, "Hello Bitcoin!");
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
```

**TypeScript:**
```typescript
import { Non_Custodial_Wallet, ThresholdSignatureResult } from 'j-bitcoin';

// Create 2-of-3 threshold wallet
const wallet: Non_Custodial_Wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);

// Get shares for distribution
const shares: string[] = wallet._shares;
console.log('Distribute shares to participants:', shares);

// Generate threshold signature
const signature: ThresholdSignatureResult = wallet.sign("Multi-party transaction");
console.log('Threshold signature:', signature.serialized_sig);
```

### Address Conversion

**JavaScript:**
```javascript
import { BECH32, CASH_ADDR } from 'j-bitcoin';

const legacyAddress = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

// Convert to SegWit
const segwitAddr = BECH32.to_P2WPKH(legacyAddress);
console.log('SegWit:', segwitAddr);
// Output: bc1qhkfq3zahaqkkzx5mjnamwjsfpw3tvke7v6aaph

// Convert to CashAddr
const cashAddr = CASH_ADDR.to_cashAddr(legacyAddress, "p2pkh");
console.log('CashAddr:', cashAddr);
// Output: bitcoincash:qztxx64w20kmy5y9sskjwtgxp3j8dc20ksvef26ssu
```

**TypeScript:**
```typescript
import { BECH32, CASH_ADDR } from 'j-bitcoin';

const legacyAddress: string = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

// Convert to SegWit
const segwitAddr: string = BECH32.to_P2WPKH(legacyAddress);
console.log('SegWit:', segwitAddr);
// Output: bc1qhkfq3zahaqkkzx5mjnamwjsfpw3tvke7v6aaph

// Convert to CashAddr
const cashAddr: string = CASH_ADDR.to_cashAddr(legacyAddress, "p2pkh");
console.log('CashAddr:', cashAddr);
// Output: bitcoincash:qztxx64w20kmy5y9sskjwtgxp3j8dc20ksvef26ssu
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

// Sign with Schnorr
const signature: Uint8Array = schnorr_sig.sign(privateKey, message);

// Get public key
const publicKey: Uint8Array = schnorr_sig.retrieve_public_key(privateKey);

// Verify signature
const isValid: boolean = schnorr_sig.verify(signature, message, publicKey);
console.log('Schnorr signature valid:', isValid);
```

## 📖 API Documentation

### TypeScript Support

J-Bitcoin provides complete TypeScript definitions with:

```typescript
// Full IntelliSense support
import type { 
  Custodial_Wallet, 
  Non_Custodial_Wallet,
  ECDSASignatureResult,
  ThresholdSignatureResult,
  HDKeys,
  KeyPair,
  NetworkType 
} from 'j-bitcoin';

// Type-safe network specification
const network: NetworkType = 'main'; // 'main' | 'test'

// Strongly typed wallet creation
const wallet: Custodial_Wallet = Custodial_Wallet.fromRandom(network);

// Comprehensive interface definitions
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
| `sign(message)` | Sign with ECDSA |
| `verify(sig, message)` | Verify signature |

### Non_Custodial_Wallet

| Method | Description |
|--------|-------------|
| `fromRandom(net, groupSize, threshold)` | Create threshold wallet |
| `fromShares(net, shares, threshold)` | Reconstruct from shares |
| `sign(message)` | Generate threshold signature |
| `verify(sig, msgHash)` | Verify threshold signature |
| `_shares` | Get secret shares |
| `_privateKey` | Get reconstructed private key |

### Address Utilities

| Function | Description |
|----------|-------------|
| `BECH32.to_P2WPKH(address)` | Convert to SegWit |
| `BECH32.data_to_bech32(prefix, data, encoding)` | Custom Bech32 encoding |
| `CASH_ADDR.to_cashAddr(address, type?)` | Convert to CashAddr |

## 🔗 BIP32 Key Derivation

**JavaScript:**
```javascript
// Standard BIP44 paths
wallet.derive("m/44'/0'/0'/0/0");    // Bitcoin account 0, address 0
wallet.derive("m/44'/145'/0'/0/0");  // Bitcoin Cash account 0
wallet.derive("m/44'/236'/0'/0/0");  // Bitcoin SV account 0

// Custom derivation
wallet.derive("m/0'/1'/2");          // Hardened path
wallet.derive("m/0/1/2");            // Non-hardened path
```

**TypeScript:**
```typescript
import { Custodial_Wallet, KeyType } from 'j-bitcoin';

// Standard BIP44 paths with type safety
wallet.derive("m/44'/0'/0'/0/0", 'pri' as KeyType);    // Bitcoin account 0, address 0
wallet.derive("m/44'/145'/0'/0/0", 'pri' as KeyType);  // Bitcoin Cash account 0
wallet.derive("m/44'/236'/0'/0/0", 'pri' as KeyType);  // Bitcoin SV account 0

// Custom derivation with type checking
wallet.derive("m/0'/1'/2", 'pri' as KeyType);          // Hardened path
wallet.derive("m/0/1/2", 'pub' as KeyType);            // Non-hardened path (public key derivation)
```

## 🛡️ Security Features

- **Secure Random Generation** - Uses Node.js crypto.randomBytes()
- **Mnemonic Validation** - BIP39 checksum verification
- **Threshold Security** - Distributed key management
- **Multiple Signature Schemes** - ECDSA, Schnorr, TSS
- **Address Validation** - Built-in format checking

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
```

**TypeScript:**
```typescript
import { Non_Custodial_Wallet } from 'j-bitcoin';

// 2-of-3 escrow: buyer, seller, arbiter
const escrow: Non_Custodial_Wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
const [buyerShare, sellerShare, arbiterShare]: string[] = escrow._shares;

// Buyer + Seller can release funds
const release: Non_Custodial_Wallet = Non_Custodial_Wallet.fromShares("main", 
  [buyerShare, sellerShare], 2);

// Disputes require arbiter
const dispute: Non_Custodial_Wallet = Non_Custodial_Wallet.fromShares("main",
  [buyerShare, arbiterShare], 2);
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
```

**TypeScript:**
```typescript
import { Non_Custodial_Wallet, ThresholdSignatureResult } from 'j-bitcoin';

// 3-of-5 corporate signature
const treasury: Non_Custodial_Wallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
const executiveShares: string[] = treasury._shares;

// Any 3 executives can authorize
const authorization: Non_Custodial_Wallet = Non_Custodial_Wallet.fromShares("main",
  [executiveShares[0], executiveShares[2], executiveShares[4]], 3);

// Type-safe signature generation
const authSignature: ThresholdSignatureResult = authorization.sign("Transfer $1M to operations");
```

### Cross-Platform Wallet

**JavaScript:**
```javascript
import { Custodial_Wallet } from 'j-bitcoin';

// Generate with passphrase
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main', 'secure-pass');

// Reconstruct anywhere
const restored = Custodial_Wallet.fromMnemonic('main', mnemonic, 'secure-pass');

// Derive for different coins
restored.derive("m/44'/0'/0'/0/0");   // Bitcoin
restored.derive("m/44'/145'/0'/0/0"); // Bitcoin Cash
restored.derive("m/44'/236'/0'/0/0"); // Bitcoin SV
```

**TypeScript:**
```typescript
import { Custodial_Wallet, NetworkType } from 'j-bitcoin';

// Type-safe network specification
const network: NetworkType = 'main';

// Generate with passphrase
const [mnemonic, wallet]: [string, Custodial_Wallet] = 
  Custodial_Wallet.fromRandom(network, 'secure-pass');

// Reconstruct anywhere with type safety
const restored: Custodial_Wallet = 
  Custodial_Wallet.fromMnemonic(network, mnemonic, 'secure-pass');

// Derive for different coins
restored.derive("m/44'/0'/0'/0/0");   // Bitcoin
restored.derive("m/44'/145'/0'/0/0"); // Bitcoin Cash
restored.derive("m/44'/236'/0'/0/0"); // Bitcoin SV
```

## 📊 Feature Matrix

| Feature | Support | TypeScript |
|---------|---------|-------------|
| Hierarchical Deterministic | ✅ | ✅ Full types |
| Threshold Signatures | ✅ | ✅ Complete interfaces |
| ECDSA Signatures | ✅ | ✅ Type-safe returns |
| Schnorr Signatures | ✅ | ✅ BIP340 types |
| P2PKH Addresses | ✅ | ✅ Network types |
| P2WPKH (SegWit) | ✅ | ✅ Bech32 types |
| CashAddr Format | ✅ | ✅ Format types |
| P2SH Addresses | ❌ | 🔄 Planned |
| P2WSH (SegWit v1) | ❌ | 🔄 Planned |
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

const wallet = Custodial_Wallet.fromRandom('main');
//    ^-- IDE shows: [string, Custodial_Wallet]

wallet.derive("m/44'/0'/0'/0/0", 'pri');
//     ^-- IDE shows available parameters and types
```

### Generate API Documentation

```bash
npm install -g jsdoc
npm run docs
```

View comprehensive documentation in `docs/index.html` with:
- **Complete API reference** with examples
- **TypeScript integration guide**
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