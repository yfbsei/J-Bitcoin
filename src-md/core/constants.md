# Bitcoin Constants & Configuration - J-Bitcoin

This module provides centralized constants and utility functions for handling Bitcoin-specific configuration in the J-Bitcoin library.

## Overview

It supports:

- BIP44/BIP49/BIP84/BIP86 derivation path standards
- Mainnet and Testnet configurations
- Address format identifiers (Legacy, SegWit, Taproot)
- Derivation path generation and parsing
- Validation of Bitcoin derivation paths

## Exports

### `BIP44_CONSTANTS`

Constants related to BIP44 key derivation.

```js
BIP44_CONSTANTS = {
  PURPOSE: 44,
  COIN_TYPES: {
    BITCOIN_MAINNET: 0,
    BITCOIN_TESTNET: 1
  },
  ACCOUNT: 0,
  CHANGE: {
    EXTERNAL: 0,
    INTERNAL: 1
  }
}
```

### `DERIVATION_PATHS`

Predefined derivation paths.

```js
DERIVATION_PATHS = {
  BITCOIN_LEGACY: "m/44'/0'/0'",
  BITCOIN_TESTNET: "m/44'/1'/0'",
  BITCOIN_RECEIVING: "m/44'/0'/0'/0",
  BITCOIN_CHANGE: "m/44'/0'/0'/1",
  BITCOIN_FIRST_ADDRESS: "m/44'/0'/0'/0/0",
  BITCOIN_FIRST_CHANGE: "m/44'/0'/0'/1/0",
  TESTNET_RECEIVING: "m/44'/1'/0'/0",
  TESTNET_CHANGE: "m/44'/1'/0'/1"
}
```

### `NETWORKS`

Network configuration for Bitcoin mainnet and testnet.

```js
NETWORKS = {
  MAINNET: {
    name: 'Bitcoin',
    symbol: 'BTC',
    coinType: 0,
    addressPrefix: 'bc',
    legacyPrefix: '1',
    p2shPrefix: '3',
    network: 'main'
  },
  TESTNET: {
    name: 'Bitcoin Testnet',
    symbol: 'BTC',
    coinType: 1,
    addressPrefix: 'tb',
    legacyPrefix: 'm',
    legacyPrefixAlt: 'n',
    p2shPrefix: '2',
    network: 'test'
  }
}
```

### `ADDRESS_FORMATS`

Supported Bitcoin address formats.

```js
ADDRESS_FORMATS = {
  LEGACY: 'legacy',
  SEGWIT: 'segwit',
  P2SH: 'p2sh'
}
```

### `BIP_PURPOSES`

BIP standards for derivation.

```js
BIP_PURPOSES = {
  LEGACY: 44,
  NESTED_SEGWIT: 49,
  NATIVE_SEGWIT: 84,
  TAPROOT: 86
}
```

## Functions

### `generateDerivationPath(options)`

Generates a full derivation path based on options.

```js
generateDerivationPath({
  purpose = 44,
  coinType = 0,
  account = 0,
  change = 0,
  addressIndex = 0
})
```

Example:

```js
generateDerivationPath({ addressIndex: 5 });
// "m/44'/0'/0'/0/5"
```

### `parseDerivationPath(path)`

Parses a derivation path into components.

```js
parseDerivationPath("m/44'/0'/0'/0/5")
```

Returns:

```js
{
  purpose: 44,
  coinType: 0,
  account: 0,
  change: 0,
  addressIndex: 5
}
```

### `isValidBitcoinPath(path)`

Checks if a derivation path is valid for Bitcoin (coinType 0 or 1).

### `getNetworkByCoinType(coinType)`

Returns network configuration for Bitcoin based on BIP44 coin type.

```js
getNetworkByCoinType(0).name // "Bitcoin"
```

---

## License

MIT