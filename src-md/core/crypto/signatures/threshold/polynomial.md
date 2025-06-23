# Polynomial Arithmetic

Comprehensive polynomial arithmetic implementation for threshold cryptography and secret sharing schemes.

## Description

This module provides complete polynomial arithmetic functionality for cryptographic applications including Shamir's Secret Sharing, threshold signatures, and polynomial interpolation. It implements secure polynomial operations over finite fields with comprehensive mathematical utilities for distributed cryptographic systems and multi-party computation protocols.

## Example

```javascript
import { 
    Polynomial,
    LagrangeInterpolation,
    FiniteField,
    SecretSharing,
    POLYNOMIAL_CONSTANTS
} from 'j-bitcoin';

// Create polynomial with coefficients
const coefficients = [5, 3, 2]; // 5 + 3x + 2x^2
const poly = new Polynomial(coefficients);
console.log('Polynomial:', poly.toString()); // "5 + 3x + 2x^2"
console.log('Degree:', poly.degree); // 2

// Evaluate polynomial at specific points
const x = 7;
const result = poly.evaluate(x);
console.log(`P(${x}) =`, result); // P(7) = 5 + 3*7 + 2*49 = 124

// Generate random polynomial for secret sharing
const secret = 12345;
const threshold = 3; // 3-of-5 threshold scheme
const participants = 5;

const secretPoly = Polynomial.generateRandom(threshold - 1, secret);
console.log('Secret polynomial degree:', secretPoly.degree); // 2 (threshold - 1)

// Generate shares for participants
const shares = [];
for (let i = 1; i <= participants; i++) {
    const share = {
        x: i,
        y: secretPoly.evaluate(i)
    };
    shares.push(share);
    console.log(`Share ${i}: (${share.x}, ${share.y})`);
}

// Reconstruct secret using Lagrange interpolation
const selectedShares = shares.slice(0, threshold); // Use first 3 shares
const reconstructed = LagrangeInterpolation.interpolateAtZero(selectedShares);
console.log('Reconstructed secret:', reconstructed.value); // Should equal 12345
console.log('Reconstruction successful:', reconstructed.value === secret);

// Polynomial arithmetic operations
const poly1 = new Polynomial([1, 2, 3]); // 1 + 2x + 3x^2
const poly2 = new Polynomial([4, 5]);    // 4 + 5x

// Addition
const sum = poly1.add(poly2);
console.log('Sum:', sum.toString()); // "5 + 7x + 3x^2"

// Multiplication
const product = poly1.multiply(poly2);
console.log('Product:', product.toString()); // "4 + 13x + 22x^2 + 15x^3"

// Modular arithmetic for finite fields
const modulus = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"); // secp256k1 order
const field = new FiniteField(modulus);

const polyMod = new Polynomial([secret, 100, 200], field);
const shares_mod = [];
for (let i = 1; i <= participants; i++) {
    shares_mod.push({
        x: BigInt(i),
        y: polyMod.evaluate(BigInt(i))
    });
}

// Secure interpolation with finite field arithmetic
const secretRecovered = LagrangeInterpolation.interpolateAtZero(
    shares_mod.slice(0, threshold),
    field
);
console.log('Finite field reconstruction:', secretRecovered.value === BigInt(secret));

// Advanced: Joint Verifiable Random Secret Sharing (JVRSS)
const jvrss = new SecretSharing.JVRSS({
    threshold: 2,
    participants: 3,
    field: field
});

const jvrssShares = await jvrss.generateShares();
console.log('JVRSS shares generated:', jvrssShares.length);

// Verify shares without revealing secret
const verification = jvrss.verifyShares(jvrssShares);
console.log('Share verification:', verification.allValid);

// Polynomial commitment scheme
const commitment = poly1.createCommitment();
console.log('Polynomial commitment:', commitment.commitments.length);

// Verify evaluation with commitment
const point = 5;
const evaluation = poly1.evaluate(point);
const proof = poly1.createEvaluationProof(point);
const verificationResult = commitment.verify(point, evaluation, proof);
console.log('Evaluation verification:', verificationResult);
```

## API Reference

### Classes

#### `Polynomial`
Main polynomial class with comprehensive arithmetic operations.

**Constructor:**
```javascript
new Polynomial(coefficients, field = null)
```

**Parameters:**
- `coefficients` (Array<number|BigInt>) - Polynomial coefficients (constant term first)
- `field` (FiniteField) - Finite field for modular arithmetic (optional)

**Properties:**
- `coefficients` (Array) - Polynomial coefficients
- `degree` (number) - Polynomial degree
- `field` (FiniteField) - Associated finite field

**Static Methods:**

##### `Polynomial.generateRandom(degree, constantTerm = null, field = null)`
Generates random polynomial with specified degree.

**Parameters:**
- `degree` (number) - Polynomial degree
- `constantTerm` (number|BigInt) - Fixed constant term (optional)
- `field` (FiniteField) - Finite field for coefficients

**Returns:**
- `Polynomial` - Random polynomial

##### `Polynomial.fromPoints(points, field = null)`
Creates polynomial from interpolation points.

**Parameters:**
- `points` (Array<Object>) - Points with `x` and `y` properties
- `field` (FiniteField) - Finite field (optional)

**Returns:**
- `Polynomial` - Interpolated polynomial

##### `Polynomial.zero(field = null)`
Creates zero polynomial.

**Returns:**
- `Polynomial` - Zero polynomial

##### `Polynomial.one(field = null)`
Creates polynomial equal to 1.

**Returns:**
- `Polynomial` - Constant polynomial 1

**Instance Methods:**

##### `poly.evaluate(x)`
Evaluates polynomial at given point using Horner's method.

**Parameters:**
- `x` (number|BigInt) - Evaluation point

**Returns:**
- `number|BigInt` - Polynomial value at x

##### `poly.add(other)`
Adds two polynomials.

**Parameters:**
- `other` (Polynomial) - Polynomial to add

**Returns:**
- `Polynomial` - Sum polynomial

##### `poly.subtract(other)`
Subtracts two polynomials.

**Parameters:**
- `other` (Polynomial) - Polynomial to subtract

**Returns:**
- `Polynomial` - Difference polynomial

##### `poly.multiply(other)`
Multiplies two polynomials.

**Parameters:**
- `other` (Polynomial) - Polynomial to multiply

**Returns:**
- `Polynomial` - Product polynomial

##### `poly.divide(other)`
Divides two polynomials.

**Parameters:**
- `other` (Polynomial) - Divisor polynomial

**Returns:**
- Object with division result:
  - `quotient` (Polynomial) - Quotient polynomial
  - `remainder` (Polynomial) - Remainder polynomial

##### `poly.derivative()`
Computes polynomial derivative.

**Returns:**
- `Polynomial` - Derivative polynomial

##### `poly.compose(other)`
Composes two polynomials: this(other(x)).

**Parameters:**
- `other` (Polynomial) - Inner polynomial

**Returns:**
- `Polynomial` - Composed polynomial

##### `poly.clone()`
Creates deep copy of polynomial.

**Returns:**
- `Polynomial` - Cloned polynomial

##### `poly.toString(variable = 'x')`
Returns string representation of polynomial.

**Parameters:**
- `variable` (string) - Variable name for display

**Returns:**
- `string` - Polynomial string representation

#### `LagrangeInterpolation`
Lagrange interpolation utilities for polynomial reconstruction.

**Static Methods:**

##### `LagrangeInterpolation.interpolate(points, field = null)`
Performs Lagrange interpolation through given points.

**Parameters:**
- `points` (Array<Object>) - Interpolation points
- `field` (FiniteField) - Finite field (optional)

**Returns:**
- `Polynomial` - Interpolated polynomial

##### `LagrangeInterpolation.interpolateAtZero(points, field = null)`
Efficiently interpolates polynomial value at zero.

**Parameters:**
- `points` (Array<Object>) - Points with `x` and `y` properties
- `field` (FiniteField) - Finite field (optional)

**Returns:**
- Object with interpolation result:
  - `value` (number|BigInt) - Polynomial value at zero
  - `coefficients` (Array) - Lagrange coefficients used

##### `LagrangeInterpolation.interpolateAt(points, x, field = null)`
Interpolates polynomial value at specific point.

**Parameters:**
- `points` (Array<Object>) - Interpolation points
- `x` (number|BigInt) - Evaluation point
- `field` (FiniteField) - Finite field (optional)

**Returns:**
- `number|BigInt` - Interpolated value at x

#### `FiniteField`
Finite field arithmetic for cryptographic applications.

**Constructor:**
```javascript
new FiniteField(modulus)
```

**Parameters:**
- `modulus` (BigInt) - Field modulus (prime number)

**Methods:**

##### `field.add(a, b)`
Modular addition.

**Parameters:**
- `a` (BigInt) - First operand
- `b` (BigInt) - Second operand

**Returns:**
- `BigInt` - (a + b) mod modulus

##### `field.subtract(a, b)`
Modular subtraction.

**Parameters:**
- `a` (BigInt) - First operand
- `b` (BigInt) - Second operand

**Returns:**
- `BigInt` - (a - b) mod modulus

##### `field.multiply(a, b)`
Modular multiplication.

**Parameters:**
- `a` (BigInt) - First operand
- `b` (BigInt) - Second operand

**Returns:**
- `BigInt` - (a * b) mod modulus

##### `field.divide(a, b)`
Modular division using modular inverse.

**Parameters:**
- `a` (BigInt) - Dividend
- `b` (BigInt) - Divisor

**Returns:**
- `BigInt` - (a * b^(-1)) mod modulus

##### `field.inverse(a)`
Computes modular inverse using extended Euclidean algorithm.

**Parameters:**
- `a` (BigInt) - Element to invert

**Returns:**
- `BigInt` - Modular inverse of a

##### `field.power(base, exponent)`
Modular exponentiation using fast exponentiation.

**Parameters:**
- `base` (BigInt) - Base value
- `exponent` (BigInt) - Exponent

**Returns:**
- `BigInt` - base^exponent mod modulus

#### `SecretSharing`
Secret sharing scheme implementations.

**Namespace containing:**

##### `SecretSharing.Shamir`
Shamir's Secret Sharing implementation.

**Methods:**

###### `Shamir.generateShares(secret, threshold, participants, field = null)`
Generates secret shares using Shamir's scheme.

**Parameters:**
- `secret` (number|BigInt) - Secret to share
- `threshold` (number) - Minimum shares needed for reconstruction
- `participants` (number) - Total number of participants
- `field` (FiniteField) - Finite field (optional)

**Returns:**
- Array of share objects:
  - `x` (number) - Share index
  - `y` (BigInt) - Share value
  - `threshold` (number) - Required threshold
  - `polynomial` (Polynomial) - Sharing polynomial (for verification)

###### `Shamir.reconstructSecret(shares, field = null)`
Reconstructs secret from shares.

**Parameters:**
- `shares` (Array) - Array of share objects (≥ threshold)
- `field` (FiniteField) - Finite field (optional)

**Returns:**
- `BigInt` - Reconstructed secret

###### `Shamir.verifyShare(share, polynomial)`
Verifies share against polynomial.

**Parameters:**
- `share` (Object) - Share to verify
- `polynomial` (Polynomial) - Original sharing polynomial

**Returns:**
- `boolean` - Whether share is valid

##### `SecretSharing.JVRSS`
Joint Verifiable Random Secret Sharing implementation.

**Constructor:**
```javascript
new SecretSharing.JVRSS(options)
```

**Options:**
- `threshold` (number) - Required threshold
- `participants` (number) - Total participants
- `field` (FiniteField) - Finite field for operations
- `commitmentScheme` (string) - Commitment scheme ('pedersen' or 'feldman')

**Methods:**

###### `jvrss.generateShares()`
Generates verifiable secret shares without trusted dealer.

**Returns:**
- Object with generation result:
  - `shares` (Array) - Generated shares for each participant
  - `commitments` (Array) - Polynomial commitments for verification
  - `proofs` (Array) - Zero-knowledge proofs
  - `publicPolynomial` (Polynomial) - Public polynomial commitment

###### `jvrss.verifyShares(shares)`
Verifies all shares using polynomial commitments.

**Parameters:**
- `shares` (Array) - Shares to verify

**Returns:**
- Object with verification result:
  - `allValid` (boolean) - Whether all shares are valid
  - `validShares` (Array<boolean>) - Per-share validation results
  - `invalidIndices` (Array<number>) - Indices of invalid shares

###### `jvrss.reconstructSharedSecret(shares)`
Reconstructs the shared secret from verified shares.

**Parameters:**
- `shares` (Array) - Verified shares

**Returns:**
- `BigInt` - Reconstructed shared secret

### Polynomial Commitment Schemes

#### Feldman's Verifiable Secret Sharing
```javascript
const feldman = new SecretSharing.Feldman({
    threshold: 3,
    participants: 5,
    generator: generatorPoint, // Elliptic curve generator
    field: secp256k1Field
});

const { shares, commitments } = feldman.generateVerifiableShares(secret);

// Anyone can verify shares without knowing the secret
const isValid = feldman.verifyShare(shares[0], commitments);
```

#### Pedersen Commitments
```javascript
const pedersen = new PolynomialCommitment.Pedersen({
    generator1: g1,
    generator2: g2,
    field: field
});

const commitment = pedersen.commit(polynomial);
const opening = pedersen.createOpening(polynomial, evaluationPoint);
const verificationResult = pedersen.verify(commitment, evaluationPoint, evaluationValue, opening);
```

### Mathematical Operations

#### Polynomial Evaluation Algorithms

##### Horner's Method
Efficient polynomial evaluation with O(n) complexity:
```
P(x) = a₀ + x(a₁ + x(a₂ + x(a₃ + ... + x(aₙ))))
```

##### Batch Evaluation
Evaluate polynomial at multiple points efficiently:
```javascript
const points = [1, 2, 3, 4, 5];
const evaluations = poly.evaluateBatch(points);
```

#### Interpolation Algorithms

##### Lagrange Interpolation
Given points (x₀,y₀), (x₁,y₁), ..., (xₙ,yₙ):
```
P(x) = Σᵢ yᵢ * Πⱼ≠ᵢ (x - xⱼ)/(xᵢ - xⱼ)
```

##### Newton Interpolation
Alternative interpolation method with divided differences:
```javascript
const newton = new NewtonInterpolation(points);
const polynomial = newton.getPolynomial();
```

#### Fast Fourier Transform (FFT)
For efficient polynomial multiplication:
```javascript
const fft = new PolynomialFFT(field);
const product = fft.multiply(poly1, poly2); // O(n log n) complexity
```

### Cryptographic Applications

#### Threshold Signatures
```javascript
// Generate polynomial for threshold signature
const signingPoly = Polynomial.generateRandom(threshold - 1, privateKey, secp256k1Field);
const signingShares = [];
for (let i = 1; i <= participants; i++) {
    signingShares.push({
        index: i,
        share: signingPoly.evaluate(BigInt(i))
    });
}

// Combine signature shares
const signatures = await Promise.all(
    signingShares.slice(0, threshold).map(share => 
        generatePartialSignature(message, share.share)
    )
);

const combinedSignature = LagrangeInterpolation.interpolateAtZero(
    signatures.map((sig, i) => ({ x: i + 1, y: sig })),
    secp256k1Field
);
```

#### Distributed Key Generation
```javascript
// Each participant generates their polynomial
const participantPolys = participants.map(i => 
    Polynomial.generateRandom(threshold - 1, null, field)
);

// Combine polynomials to get shared polynomial
const sharedPoly = participantPolys.reduce((sum, poly) => sum.add(poly));

// Generate final key shares
const keyShares = [];
for (let i = 1; i <= participants; i++) {
    keyShares.push({
        participant: i,
        share: sharedPoly.evaluate(BigInt(i))
    });
}
```

#### Zero-Knowledge Proofs
```javascript
// Prove knowledge of polynomial evaluation
const zkProof = polynomial.createEvaluationProof(challengePoint);
const isValidProof = verifyEvaluationProof(
    commitment,
    challengePoint,
    claimedValue,
    zkProof
);
```

### Security Features

- **Secure Random Generation** - Cryptographically secure coefficient generation
- **Constant-Time Operations** - Timing attack prevention for sensitive operations
- **Input Validation** - Comprehensive validation of all mathematical inputs
- **Memory Safety** - Secure handling of sensitive polynomial coefficients
- **Field Validation** - Proper finite field arithmetic with overflow protection
- **Share Verification** - Cryptographic verification of secret shares
- **Zero-Knowledge Proofs** - Privacy-preserving polynomial operations

### Performance Optimization

#### Algorithmic Optimizations
- **Horner's Method** - O(n) polynomial evaluation
- **FFT Multiplication** - O(n log n) polynomial multiplication
- **Precomputed Inverses** - Cache modular inverses for repeated operations
- **Batch Operations** - Process multiple operations together

#### Memory Optimizations
- **Coefficient Compression** - Minimize storage for sparse polynomials
- **Lazy Evaluation** - Compute values only when needed
- **Memory Pooling** - Reuse allocated memory for temporary operations
- **Garbage Collection** - Automatic cleanup of intermediate results

### Error Handling

#### Error Types
- `POLYNOMIAL_INVALID_COEFFICIENTS` - Invalid coefficient array
- `POLYNOMIAL_DEGREE_MISMATCH` - Degree mismatch in operations
- `INTERPOLATION_INSUFFICIENT_POINTS` - Not enough points for interpolation
- `INTERPOLATION_DUPLICATE_X` - Duplicate x-coordinates in interpolation
- `FIELD_DIVISION_BY_ZERO` - Division by zero in finite field
- `FIELD_INVALID_MODULUS` - Invalid field modulus
- `SECRET_SHARING_INVALID_THRESHOLD` - Invalid threshold parameters
- `SECRET_SHARING_INSUFFICIENT_SHARES` - Not enough shares for reconstruction

### Best Practices

1. **Use appropriate field sizes** for cryptographic security
2. **Validate all inputs** before polynomial operations
3. **Clear sensitive coefficients** after use
4. **Use constant-time operations** for secret-dependent computations
5. **Verify reconstructed secrets** against known commitments
6. **Implement proper error handling** for all mathematical operations
7. **Use secure random number generation** for coefficient generation
8. **Test edge cases** thoroughly (zero polynomials, single points, etc.)
9. **Monitor performance** for large-degree polynomials
10. **Keep cryptographic parameters updated** with current security standards

### Integration Examples

#### With Threshold Signatures
```javascript
const threshold = 2;
const participants = 3;
const message = "transaction_to_sign";

// Generate signing polynomial
const signingPoly = Polynomial.generateRandom(
    threshold - 1, 
    privateKey, 
    secp256k1Field
);

// Distribute shares and collect signatures
const partialSignatures = await collectPartialSignatures(
    message, 
    signingPoly, 
    participants
);

// Combine using interpolation
const finalSignature = LagrangeInterpolation.interpolateAtZero(
    partialSignatures,
    secp256k1Field
);
```

#### With Multi-Party Computation
```javascript
// Secure multi-party polynomial evaluation
const mpcEvaluation = await secureEvaluate(
    encryptedPolynomial,
    encryptedPoint,
    participants
);
```

#### With Commitment Schemes
```javascript
const commitment = polynomial.createPedersenCommitment(randomness);
const opening = polynomial.createOpening(evaluationPoint);
const verified = commitment.verify(evaluationPoint, evaluationValue, opening);
```