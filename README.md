# J-Bitcoin
Bitcoin Custodial &amp; non-Custodial Wallets

| Coin  | Custodial & non-Custodial Wallet Support |
| ----- | -------------- |
|  BTC  | ✔️ |
|  BCH  | ✔️ |
|  BSV  | ✔️ |

## Getting started
`npm i j-bitcoin`
\
\
`import { Custodial_Wallet, Non_Custodial_Wallet } from 'j-bitcoin';`

## Custodial Wallet

### Generate wallet

`const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main'); // main network`
\
`const [mnemonic, wallet] = Custodial_Wallet.fromRandom('test'); // test network`

### Import from mnemonic
```
const 
    mnemonic = "teach scatter sample solar casino festival decrease pause random drip memory mystery",
    wallet = Custodial_Wallet.fromMnemonic('main', mnemonic);
```

### Import from seed
```
const 
    seed = "000102030405060708090a0b0c0d0e0f",
    wallet = Custodial_Wallet.fromSeed('main', seed);
```

### Password
```
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main', 'password123');
// ...
const wallet = Custodial_Wallet.fromMnemonic('main', mnemonic, 'password123');
// Incorrect password returns random wallet
```

### Derive child 
`wallet.derive("m/0", 'pri');`
\
\
Public Keys can't derive from a hardend path
`wallet.derive("m/0'", 'pub'); // Throws Error`

### Signature - ECDSA
`const message = "Jamallo";`
\
sign
\
`const [sig, recovery] = wallet.sign(message);`

verfiy signature
\
`wallet.verify(sig, message); // true`


## Non-Custodial Wallet

##### Threshold Signature Scheme (TSS) wallet

### Generate wallet
`const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2); // main network`
\
`const wallet = Non_Custodial_Wallet.fromRandom("test", 3, 2); // test network`

### Import from shares
```
const shares = [
    '79479395a59a8e9d930f2b10ccd5ac3671b0ff0bf8a66aaa1d74978c5353694b',
    '98510126c920e18b148130ac1145686cb299d21f0e010b98ede44169a7bb1c13',
    'b75a6eb7eca7347895f3364755b524a2f382a532235bac87be53eb46fc22cedb'
  ]

const wallet = Non_Custodial_Wallet.fromShares("main", shares, 2);
```

### Shares
`const share_for_each_participant = wallet._shares;`

### Restore private key
`const groups_prikey = wallet._privateKey;`

### Signature - TSS
sign
\
`const { sig, serialized_sig, msgHash, recovery_id } = wallet.sign("hello world");`

verfiy signature
\
`wallet.verify(sig, msgHash); // true`

## Address conversion
`import { CASH_ADDR, BECH32 } from 'j-bitcoin';`

### CashAddr (BCH)
```
 wallet.address; // 1EiBTNS9Dqhjhk7D78GMAjK9pZn5NXZf91
 CASH_ADDR.to_cashAddr(wallet.address); // bitcoincash:qztxx64w20kmy5y9sskjwtgxp3j8dc20ksvef26ssu

 wallet.address; // mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D 
 CASH_ADDR.to_cashAddr(wallet.address); // bchtest:qqyl7uye7t0rjq6vrtqjedcyudy8hj0rzvnwwa5c5g
```

### P2WPKH (BTC)
```
  wallet.address; // 1EiBTNS9Dqhjhk7D78GMAjK9pZn5NXZf91
  BECH32.to_P2WPKH(wallet.address); // bc1qje3k4tjnake9ppvy95nj6psvv3mwzna5uatznl

  wallet.address; // mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D
  BECH32.to_P2WPKH(wallet.address); // tb1qp8lhpx0jmcusxnq6cyktwp8rfpaunccntw8kty
```
## Schnorr signature
`import { schnorr_sig } from 'j-bitcoin';`
\
\
`const [private_key, message] = ["L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", "Jamallo"];`
\
\
sign 
\
`const signature = schnorr_sig.sign(private_key, message);`
\
\
retrieve public key
\
`const public_key = schnorr_sig.retrieve_public_key(private_key);`
\
\
verfiy siganture
\
`schnorr_sig.verify(signature, message, public_key); // true`  

## Info

| Wallet  | Support |
| ----- | ------------ |
| Hierarchical deterministic | ✔️ |
| Threshold signature scheme | ✔️ |
| SPV | ❌️ |

| Signature  | Support |
| ----- | ------------ |
| ECDSA | ✔️ |
| Threshold Signature  | ✔️ |
| Schnorr signature  | ✔️ |

| Address  | Support |
| ----- | ------------ |
| P2PKH | ✔️ |
| P2WPKH | ✔️ |
| P2SH  | ❌️ |
| P2WSH | ❌️ |
| Cashaddr | ✔️️ |

| Transaction | Support |
| ----- | ------------ |
| BTC | ❌ |
| BCH | ❌ ️|
| BSV | ❌ |

  ### TODO
- P2SH
- P2WSH
- Transactions
- SPV wallet
- QR codes
