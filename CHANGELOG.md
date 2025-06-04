# Changelog

All notable changes to J-Bitcoin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-12-19

### BREAKING CHANGES
- **Removed Bitcoin Cash (BCH) support** - All BCH-related functionality removed
- **Removed Bitcoin SV (BSV) support** - All BSV-related functionality removed  
- **Removed CashAddr format support** - No longer supports BCH address format
- **Bitcoin-only focus** - Library now exclusively supports Bitcoin (BTC)
- **Error handling improvements** - All errors now throw proper Error objects instead of strings

### Removed
- `CASH_ADDR` namespace and all CashAddr functionality
- BCH and BSV network configurations (`BCH_MAIN`, `BCH_TEST`, `BSV_MAIN`, `BSV_TEST`)
- Multi-currency derivation path examples in documentation
- `src/altAddress/BCH/` directory and all BCH utilities
- `src/ECDSA/BSV-sighHash.txt` file
- BCH/BSV coin type references in BIP44 examples
- Keywords: `bitcoin-cash`, `bitcoin-sv`, `bch`, `bsv`, `cashaddr`

### Added
- **Bitcoin-specific constants** - New `src/utilities/constants.js` module
  - `BIP44_CONSTANTS` - BIP44 derivation path constants for Bitcoin
  - `DERIVATION_PATHS` - Standard Bitcoin derivation paths
  - `BITCOIN_NETWORKS` - Bitcoin mainnet and testnet configurations
  - `ADDRESS_FORMATS` - Address format identifiers
  - `BIP_PURPOSES` - BIP purpose constants for different address types
- **Utility functions** for Bitcoin operations
  - `generateDerivationPath()` - Generate BIP44 derivation paths
  - `parseDerivationPath()` - Parse derivation paths into components
  - `isValidBitcoinPath()` - Validate Bitcoin derivation paths
  - `getNetworkByCoinType()` - Get network config by coin type
- **Enhanced TypeScript definitions** for Bitcoin-only operations
- **Improved documentation** with Bitcoin-focused examples
- **Address helper utilities** - Extracted shared functions to `src/utilities/addressHelpers.js`
- **Integrated wallet functionality**
  - `Custodial_Wallet.deriveReceivingAddress()` - Standard BIP44 receiving addresses
  - `Custodial_Wallet.deriveChangeAddress()` - Standard BIP44 change addresses
  - `Custodial_Wallet.deriveTestnetAddress()` - Testnet address generation
  - `Custodial_Wallet.getChildKeysByType()` - Filter child keys by address type
  - `Custodial_Wallet.getSummary()` - Wallet summary information
  - `Non_Custodial_Wallet.getSummary()` - Threshold wallet summary
- **Enhanced security warnings** - Runtime warnings for sensitive operations
- **Network configuration integration** - Automatic network config assignment

### Changed
- **Updated derivation path examples** to Bitcoin-only (coin types 0 and 1)
- **Simplified network configuration** to mainnet/testnet only
- **Enhanced TypeScript support** with Bitcoin-specific types and interfaces
- **Improved Bech32 implementation** with extracted helper functions
- **Updated documentation** to reflect Bitcoin-only focus
- **Streamlined codebase** for Bitcoin-specific operations
- **Version bump** to 2.0.0 indicating major breaking changes
- **Enhanced error handling** - All functions now throw proper Error objects
- **Improved input validation** - Network parameters validated in constructors
- **Constants integration** - Wallet classes now use integrated Bitcoin constants
- **Better type safety** - Enhanced TypeScript definitions with proper interfaces

### Fixed
- **Removed circular dependencies** by extracting shared utilities
- **Improved error handling** for Bitcoin address validation
- **Better type safety** for Bitcoin operations
- **Consistent naming** for Bitcoin-only functions
- **Proper error objects** - BIP39 functions now throw Error objects instead of strings
- **Network validation** - Wallet constructors validate network parameters
- **Security warnings** - Added runtime warnings for private key reconstruction
- **Documentation alignment** - Removed all BCH/BSV references from examples

### Security
- **Enhanced private key warnings** - Runtime security warnings for sensitive operations
- **Network validation** - Proper validation of network parameters
- **Input sanitization** - Improved validation throughout the library
- **Error information** - Better error messages without exposing sensitive data

### Migration Guide

#### Code Changes Required
1. **Remove CashAddr imports**:
   ```javascript
   // Remove this
   import { CASH_ADDR } from 'j-bitcoin';
   
   // Use Bitcoin-only features instead
   import { BECH32 } from 'j-bitcoin';
   ```

2. **Update derivation paths**:
   ```javascript
   // Old (remove these)
   wallet.derive("m/44'/145'/0'/0/0"); // Bitcoin Cash
   wallet.derive("m/44'/236'/0'/0/0"); // Bitcoin SV
   
   // New (Bitcoin only)
   wallet.derive("m/44'/0'/0'/0/0");   // Bitcoin mainnet
   wallet.derive("m/44'/1'/0'/0/0");   // Bitcoin testnet
   
   // Or use new convenience methods
   wallet.deriveReceivingAddress(0);   // Standard BIP44 receiving
   wallet.deriveChangeAddress(0);      // Standard BIP44 change
   wallet.deriveTestnetAddress(0);     // Testnet address
   ```

3. **Use new Bitcoin constants**:
   ```javascript
   import { 
     BIP44_CONSTANTS, 
     DERIVATION_PATHS, 
     generateDerivationPath 
   } from 'j-bitcoin';
   
   // Generate standard Bitcoin receiving address path
   const path = generateDerivationPath({
     coinType: BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET,
     addressIndex: 0
   });
   ```

4. **Update network references**:
   ```javascript
   // Old
   import { NETWORKS } from 'j-bitcoin';
   console.log(NETWORKS.BCH_MAIN); // No longer exists
   
   // New
   import { NETWORKS, BITCOIN_NETWORKS } from 'j-bitcoin';
   console.log(NETWORKS.BTC_MAIN);           // Still available
   console.log(BITCOIN_NETWORKS.MAINNET);   // New detailed config
   ```

5. **Enhanced error handling**:
   ```javascript
   // Errors are now proper Error objects
   try {
     const seed = BIP39.mnemonic2seed("invalid mnemonic");
   } catch (error) {
     console.log(error.message); // Proper error message
     console.log(error instanceof Error); // true
   }
   ```

#### TypeScript Changes
1. **Updated type definitions** for Bitcoin-only operations
2. **New utility types** for derivation paths and network configurations
3. **Enhanced IntelliSense** support for Bitcoin-specific functions
4. **Improved interface definitions** with comprehensive wallet summaries

#### Feature Replacements
| Removed Feature | Bitcoin Replacement |
|------------------|-------------------|
| `CASH_ADDR.to_cashAddr()` | `BECH32.to_P2WPKH()` |
| BCH derivation paths | Bitcoin testnet paths (`m/44'/1'/0'/0/0`) |
| Multi-currency examples | Bitcoin mainnet/testnet examples |
| CashAddr format | Bech32 SegWit format |
| String error throwing | Proper Error objects |

#### Benefits of Migration
- **Smaller bundle size** - Reduced by ~40% with removed BCH/BSV code
- **Better performance** - Optimized for Bitcoin-only operations
- **Enhanced security** - Focused codebase reduces attack surface and adds security warnings
- **Improved maintainability** - Single-currency focus simplifies updates
- **Better TypeScript support** - More precise types for Bitcoin operations
- **Enhanced developer experience** - Integrated constants and utility functions
- **Improved error handling** - Proper Error objects with better messages

---

## [1.0.2] - 2024-XX-XX

### Fixed
- Minor bug fixes and performance improvements
- Documentation updates

### Added
- Additional examples for multi-currency support
- Improved error messages

---

## [1.0.1] - 2024-XX-XX

### Fixed
- Package.json export configuration
- TypeScript definition improvements

### Added
- Additional JSDoc documentation
- Example usage files

---

## [1.0.0] - 2024-XX-XX

### Added
- Initial release of J-Bitcoin library
- **Custodial wallet** implementation with HD key derivation
- **Non-custodial threshold signature** wallet implementation
- **BIP32** hierarchical deterministic wallet support
- **BIP39** mnemonic phrase generation and validation
- **Multi-currency support** for Bitcoin (BTC), Bitcoin Cash (BCH), and Bitcoin SV (BSV)
- **Address format support**:
  - Legacy P2PKH addresses
  - SegWit Bech32 addresses  
  - Bitcoin Cash CashAddr format
- **Signature algorithms**:
  - ECDSA signatures with recovery
  - Schnorr signatures (BIP340)
  - Threshold signatures for multi-party control
- **Cryptographic features**:
  - Polynomial arithmetic for secret sharing
  - Shamir's Secret Sharing implementation
  - Joint Verifiable Random Secret Sharing (JVRSS)
- **Developer experience**:
  - Complete TypeScript definitions
  - Comprehensive JSDoc documentation
  - ES modules with tree shaking support
  - Modern JavaScript features

### Features
- Support for Bitcoin mainnet and testnet
- Support for Bitcoin Cash mainnet and testnet
- Support for Bitcoin SV mainnet and testnet
- Threshold signature schemes (2-of-3, 3-of-5, etc.)
- Mnemonic phrase backup and recovery
- Cross-platform wallet compatibility
- Hardware wallet integration ready

---

## Development Guidelines

### Version Numbering
- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions  
- **PATCH** version for backwards-compatible bug fixes

### Breaking Changes
Breaking changes are documented with migration guides and marked with **BREAKING CHANGES** in the changelog.

### Deprecation Policy
Features are deprecated for at least one minor version before removal, with clear migration paths provided.