# Polynomial Operations for Secret Sharing — `Polynomial`

This module implements **finite field polynomial arithmetic** over the secp256k1 curve order. It's optimized for cryptographic schemes like **Shamir’s Secret Sharing**, **threshold signatures**, and **secure key splitting**.

> Uses [BN.js](https://github.com/indutny/bn.js/) for big number math and operates modulo `secp256k1` curve order.

---

## ✨ Features

- 🎲 Cryptographically secure random polynomial generation
- 📈 Polynomial evaluation using **Horner’s method**
- 🔁 **Lagrange interpolation** to reconstruct secrets from shares
- ➕ Polynomial addition (f + g)
- ✖️ Polynomial multiplication (f × g)

---

## 🔧 Usage

### Create a Random Polynomial
```js
const poly = Polynomial.fromRandom(2); // Degree 2 => 3-of-N threshold
```

### Generate Shares
```js
const shares = [1, 2, 3, 4, 5].map(x => [x, poly.evaluate(x)]);
```

### Reconstruct Secret from Shares
```js
const secret = Polynomial.interpolate_evaluate(shares.slice(0, 3), 0);
```

### Add Two Polynomials
```js
const f = Polynomial.fromRandom(2);
const g = Polynomial.fromRandom(2);
const sum = f.add(g);
```

### Multiply Two Polynomials
```js
const product = f.multiply(g);
```

---

## 📘 API Reference

### `new Polynomial(coefficients: BN[])`
Create a polynomial from BigNumber coefficients.
```js
const poly = new Polynomial([new BN(3), new BN(2), new BN(1)]); // 3 + 2x + 1x²
```

---

### `Polynomial.fromRandom(order = 2)`
Generates a cryptographically secure random polynomial of given degree.
- **Returns:** `Polynomial`
- Constant term is the secret.

---

### `poly.evaluate(x)`
Evaluates the polynomial at a given `x` using Horner’s method.
- **Returns:** `{BN}` result mod curve order

---

### `Polynomial.interpolate_evaluate(points, x)`
Performs Lagrange interpolation to reconstruct f(x) from share points.
- **Parameters:**
  - `points` `{Array<[number, BN]>}` – Array of `[x, y]` shares
  - `x` `{number}` – Point at which to evaluate
- **Returns:** `{BN}` f(x) mod curve order

---

### `poly.add(other)`
Adds two polynomials coefficient-wise.
- **Returns:** `Polynomial`

---

### `poly.multiply(other)`
Multiplies two polynomials via convolution.
- **Returns:** `Polynomial`

---

## 🧠 Use Case: Shamir Secret Sharing
```js
const secret = new BN("deadbeef", "hex");
const poly = new Polynomial([secret, new BN(123), new BN(456)]); // 2-of-3

// Generate shares
const shares = [1, 2, 3].map(x => [x, poly.evaluate(x)]);

// Reconstruct from any 2
const reconstructed = Polynomial.interpolate_evaluate(shares.slice(0, 2), 0);
console.log(reconstructed.eq(secret)); // true
```

---

## 📌 Notes

- All operations are performed modulo the `secp256k1` curve order `N`
- Compatible with ECC-based threshold cryptography and MPC

```diff
+ Use this module to power secure key splitting and threshold wallet infrastructure.
```
