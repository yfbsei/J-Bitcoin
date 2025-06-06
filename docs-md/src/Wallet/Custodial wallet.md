# Wallet

# Custodial_Wallet

## 🧪 Examples

### Create a New Wallet
```js
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
console.log(mnemonic);         // 12-word phrase
console.log(wallet.address);  // Bitcoin address
```

### Import From Mnemonic
```js
const mnemonic = "abandon abandon ... about";
const wallet = Custodial_Wallet.fromMnemonic('main', mnemonic);
console.log(wallet.address);
```

### Derive Addresses
```js
wallet.deriveReceivingAddress(0);  // m/44'/0'/0'/0/0
wallet.deriveChangeAddress(0);     // m/44'/0'/0'/1/0
wallet.deriveTestnetAddress(0);    // m/44'/1'/0'/0/0
```

---

## 🧠 API Reference

### `Custodial_Wallet.fromRandom(net = 'main', passphrase = '')`
Generates a new wallet with random mnemonic.

### `Custodial_Wallet.fromMnemonic(net, mnemonic, passphrase = '')`
Restores wallet from a BIP39 mnemonic phrase.

### `Custodial_Wallet.fromSeed(net, seed)`
Restores wallet directly from a hex seed.

### `wallet.derive(path, keyType)`
Derives a child key using a custom BIP32 path.

### `wallet.deriveReceivingAddress(index)`
Shortcut for m/44'/coinType'/0'/0/index

### `wallet.deriveChangeAddress(index)`
Shortcut for m/44'/coinType'/0'/1/index

### `wallet.deriveTestnetAddress(index)`
Always derives testnet address regardless of current wallet network.

### `wallet.getChildKeysByType(type)`
Returns an array of derived keys of a specific type: `receiving`, `change`, `testnet`.

### `wallet.sign(message)`
Signs a message using ECDSA with deterministic nonce.

### `wallet.verify(signature, message)`
Verifies a signature using this wallet's public key.

### `wallet.getSummary()`
Returns a summary of wallet data including number of derived keys and addresses.