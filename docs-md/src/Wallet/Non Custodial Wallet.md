## 🧪 Examples

### Create a 2-of-3 Threshold Wallet
```js
const wallet = new Non_Custodial_Wallet('main', 3, 2);
console.log('Group size:', wallet.group_size);     // 3
console.log('Threshold:', wallet.threshold);       // 2
console.log('Address:', wallet.address);           // Bitcoin address
console.log('Shares:', wallet._shares.length);     // 3 hex-encoded shares
```

### Generate Using Factory Method
```js
const multiSigWallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
console.log('Multi-sig address:', multiSigWallet.address);

const [share1, share2, share3] = multiSigWallet._shares;
console.log('Share 1:', share1); // Hex-encoded secret share
```

### Reconstruct Wallet From Shares
```js
const shares = [
  "79479395a59a8e9d930f2b10ccd5ac36...",
  "98510126c920e18b148130ac1145686c...",
  "b7428d37e5847f9a8b3d4c2f9a1e5c8d..."
];

const wallet = Non_Custodial_Wallet.fromShares("main", shares, 2);
console.log('Reconstructed address:', wallet.address);
```

### Access Secret Shares
```js
const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
const shares = wallet._shares;
console.log('Number of shares:', shares.length);
console.log('Share format:', shares[0]); // hex string
```

### Emergency Private Key Extraction
```js
const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
console.warn('Reconstructing private key - this defeats threshold security!');
console.log('WIF Private Key:', wallet._privateKey);
```

### Signature Verification
```js
const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
const message = "Multi-party authorization required";

const signature = wallet.sign(message);  // Hypothetical signing
const isValid = wallet.verify(signature.sig, signature.msgHash);
console.log('Threshold signature valid:', isValid);
```

### Wallet Summary
```js
const wallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
console.log(wallet.getSummary());
// {
//   network: "Bitcoin",
//   address: "1BvBM...",
//   thresholdScheme: "3-of-5",
//   participants: 5,
//   requiredSigners: 3,
//   securityLevel: "High"
// }
```

---

## 🧠 API Reference

### `constructor(net, group_size, threshold)`
Creates a new instance with specified threshold parameters.

### `static fromRandom(net = "main", group_size = 3, threshold = 2)`
Generates a fresh threshold wallet using secure randomness.

### `static fromShares(net = "main", shares, threshold = 2)`
Reconstructs a wallet from existing secret shares.

### `get _shares`
Returns hex-encoded secret shares for distribution.

### `get _privateKey`
Reconstructs the full WIF-encoded private key (use with caution).

### `verify(sig, msgHash)`
Verifies a threshold signature using the public key.

### `getSummary()`
Returns wallet summary: network, address, participants, threshold, etc.
