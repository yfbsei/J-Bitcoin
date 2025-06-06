/**
 * @fileoverview Threshold Signature Scheme implementation for distributed cryptography
 * 
 * This module implements a complete threshold signature scheme using Shamir's Secret Sharing
 * and elliptic curve cryptography following the Nakasendo Threshold Signatures specification.
 * It enables distributed key generation, secret sharing, and threshold signature creation 
 * where any t-of-n participants can collaboratively generate valid signatures without 
 * reconstructing the private key.
 * 
 * The implementation includes:
 * - Joint Verifiable Random Secret Sharing (JVRSS) for distributed key generation
 * - Additive Secret Sharing (ADDSS) for linear operations on shared secrets
 * - Polynomial Reconstruction Secret Sharing (PROSS) for multiplicative operations
 * - Inverse Secret Sharing (INVSS) for computing modular inverses of shared secrets
 * - Threshold ECDSA signature generation with proper validation
 * 
 * @see {@link https://web.archive.org/web/20211216212202/https://nakasendoproject.org/Threshold-Signatures-whitepaper-nchain.pdf|Nakasendo Threshold Signatures Whitepaper}
 * @see {@link https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing|Shamir's Secret Sharing}
 * @see {@link https://en.wikipedia.org/wiki/Threshold_cryptosystem|Threshold Cryptography}
 * @see {@link https://eprint.iacr.org/2019/114.pdf|Fast Multiparty Threshold ECDSA with Fast Trustless Setup}
 * @author yfbsei
 * @version 2.0.0
 */

import Polynomial from './polynomial.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';
import { createHash } from 'node:crypto';
import { bufToBigint } from 'bigint-conversion';
import {
	CRYPTO_CONSTANTS,
	THRESHOLD_CONSTANTS
} from '../../../constants.js';
import {
	validateThresholdParams,
	assertValid
} from '../../../../utils/validation.js';

/**
 * secp256k1 curve order for modular arithmetic
 * @constant {BN}
 */
const CURVE_ORDER = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, "hex");

/**
 * @typedef {Object} ThresholdSignatureResult
 * @property {Object} signature - ECDSA signature object with r and s components
 * @property {bigint} signature.r - Signature r value as BigInt
 * @property {bigint} signature.s - Signature s value as BigInt
 * @property {string} serializedSignature - Base64-encoded compact signature format
 * @property {Buffer} messageHash - SHA256 hash of the signed message
 * @property {number} recoveryId - Recovery ID for public key recovery (0-3)
 */

/**
 * @typedef {Array<Array<BN>>} SharePoints
 * @description Array of [x, y] coordinate pairs for polynomial interpolation
 * @example [[new BN(1), share1], [new BN(2), share2], [new BN(3), share3]]
 */

/**
 * @typedef {Object} DistributedKeyGeneration
 * @property {BN[]} secretShares - Array of secret shares for each participant
 * @property {Object} aggregatePublicKey - Combined public key from all participants
 * @property {Polynomial[]} polynomials - Individual polynomials used in generation
 */

/**
 * Threshold Signature Scheme implementation for distributed cryptography
 * 
 * This class implements a complete threshold signature scheme that allows any subset
 * of participants (meeting the threshold) to collaboratively generate valid ECDSA
 * signatures without ever reconstructing the private key. The scheme is based on
 * Shamir's Secret Sharing and provides the following security guarantees:
 * 
 * **Security Properties (Nakasendo Specification):**
 * - **Threshold Security**: Requires exactly t participants to generate signatures
 * - **Information-Theoretic Privacy**: < t participants learn nothing about the private key
 * - **Robustness**: Works even if some participants are unavailable (up to n-t)
 * - **Unforgeability**: Signatures are cryptographically secure and unforgeable
 * - **Non-Interactive**: After setup, signatures can be generated without interaction
 * 
 * **Key Features:**
 * - Distributed key generation without trusted dealer (JVRSS)
 * - Threshold ECDSA signature generation
 * - Support for linear and multiplicative operations on shared secrets
 * - Compatible with standard ECDSA verification
 * - Efficient polynomial-based secret sharing
 * 
 * **Use Cases:**
 * - Multi-signature wallets and escrow services
 * - Corporate treasury management with distributed control
 * - Cryptocurrency exchanges with operator separation
 * - Secure key management for high-value assets
 * - Compliance requirements for multi-party authorization
 * 
 * @class ThresholdSignature
 * @example
 * // Create a 2-of-3 threshold signature scheme
 * const thresholdSigner = new ThresholdSignature(3, 2);
 * 
 * // Generate a threshold signature
 * const signature = thresholdSigner.sign("Transfer $1000 to Alice");
 * 
 * // Verify the signature
 * const isValid = ThresholdSignature.verifyThresholdSignature(
 *   thresholdSigner.aggregatePublicKey, 
 *   signature.messageHash, 
 *   signature.signature
 * );
 * 
 * @example
 * // Corporate treasury with 3-of-5 executive approval
 * const corporateThresholdSigner = new ThresholdSignature(5, 3);
 * const executiveShares = corporateThresholdSigner.secretShares;
 * 
 * // Distribute shares to 5 executives
 * // Any 3 can authorize transactions
 * const authSignature = corporateThresholdSigner.sign("Quarterly dividend payment");
 * 
 * @example
 * // Escrow service with dispute resolution
 * const escrowThresholdSigner = new ThresholdSignature(3, 2);
 * const [buyerShare, sellerShare, arbiterShare] = escrowThresholdSigner.secretShares;
 * 
 * // Normal case: buyer + seller release funds
 * // Dispute case: buyer/seller + arbiter resolve
 */
class ThresholdSignature {

	/**
	 * Creates a new threshold signature scheme instance
	 * 
	 * Initializes the threshold cryptographic system with specified parameters
	 * and generates the initial shared secret distribution. The constructor
	 * performs the following operations:
	 * 
	 * 1. **Parameter Validation**: Ensures threshold constraints are met
	 * 2. **JVRSS Execution**: Runs Joint Verifiable Random Secret Sharing
	 * 3. **Key Generation**: Creates distributed private key shares
	 * 4. **Public Key Derivation**: Computes the corresponding public key
	 * 
	 * **Threshold Constraints (Nakasendo Specification):**
	 * - requiredSigners ≥ 2 (minimum for meaningful security)
	 * - requiredSigners ≤ participantCount (cannot exceed total participants)
	 * - participantCount ≥ 2 (minimum for distribution)
	 * - Recommended: requiredSigners ≤ (participantCount + 1) / 2 for practical usability
	 * 
	 * @param {number} [participantCount=3] - Total number of participants in the scheme
	 * @param {number} [requiredSigners=2] - Minimum number of participants needed for operations
	 * @throws {Error} If threshold constraints are violated
	 * 
	 * @example
	 * // Create a 2-of-3 threshold scheme
	 * const thresholdSigner = new ThresholdSignature(3, 2);
	 * console.log('Participant count:', thresholdSigner.participantCount);    // 3
	 * console.log('Required signers:', thresholdSigner.requiredSigners);      // 2
	 * console.log('Polynomial degree:', thresholdSigner.polynomialDegree);    // 1 (requiredSigners - 1)
	 * console.log('Secret shares:', thresholdSigner.secretShares.length);     // 3 BigNumber shares
	 * 
	 * @example
	 * // Create a 5-of-7 corporate scheme
	 * const corporateThresholdSigner = new ThresholdSignature(7, 5);
	 * console.log('Polynomial degree:', corporateThresholdSigner.polynomialDegree); // 4 (5 - 1)
	 * 
	 * @example
	 * // Error cases
	 * try {
	 *   new ThresholdSignature(3, 5); // requiredSigners > participantCount
	 * } catch (error) {
	 *   console.log(error.message); // Descriptive validation error
	 * }
	 * 
	 * try {
	 *   new ThresholdSignature(3, 1); // requiredSigners < 2
	 * } catch (error) {
	 *   console.log(error.message); // Descriptive validation error
	 * }
	 */
	constructor(participantCount = 3, requiredSigners = 2) {
		// Validate threshold parameters using utility function
		const validation = validateThresholdParams(participantCount, requiredSigners);
		assertValid(validation);

		/**
		 * Total number of participants in the threshold scheme
		 * @type {number}
		 * @readonly
		 */
		this.participantCount = participantCount;

		/**
		 * Polynomial degree (requiredSigners - 1) for secret sharing
		 * @type {number}
		 * @readonly
		 */
		this.polynomialDegree = requiredSigners - 1;

		/**
		 * Minimum number of participants needed for cryptographic operations
		 * @type {number}
		 * @readonly
		 */
		this.requiredSigners = requiredSigners;

		/**
		 * Threshold scheme identifier string
		 * @type {string}
		 * @readonly
		 */
		this.schemeId = `${requiredSigners}-of-${participantCount}`;

		// Generate distributed key shares and aggregate public key using JVRSS
		const keyGeneration = this.generateJointVerifiableShares();

		/**
		 * Secret shares for each participant (distributed private key material)
		 * @type {BN[]}
		 * @readonly
		 */
		this.secretShares = keyGeneration.secretShares;

		/**
		 * Aggregate public key computed from all polynomial constants
		 * @type {Object}
		 * @readonly
		 */
		this.aggregatePublicKey = keyGeneration.aggregatePublicKey;

		/**
		 * Individual polynomials used in key generation (for advanced operations)
		 * @type {Polynomial[]}
		 * @readonly
		 */
		this.generationPolynomials = keyGeneration.polynomials;
	}

	/**
	 * Converts share values to coordinate points for polynomial interpolation
	 * 
	 * Transforms an array of share values into the coordinate format required
	 * for Lagrange interpolation. Each share at index i becomes a point (i+1, share)
	 * since polynomial evaluation uses 1-based indexing (x=0 is reserved for secrets).
	 * 
	 * **Indexing Convention:**
	 * - Participant indices start at 1 (not 0) for mathematical consistency
	 * - x=0 is reserved for the secret value in Shamir's Secret Sharing
	 * - Points are formatted as [x_coordinate, y_coordinate] for interpolation
	 * 
	 * @param {BN[]} shares - Array of BigNumber share values to convert
	 * @returns {SharePoints} Array of [x, y] coordinate pairs for interpolation
	 * @throws {Error} If shares array is invalid
	 * 
	 * @example
	 * const thresholdSigner = new ThresholdSignature(3, 2);
	 * const points = thresholdSigner.convertSharesToPoints(thresholdSigner.secretShares);
	 * console.log(points);
	 * // [[new BN(1), share1_value], [new BN(2), share2_value], [new BN(3), share3_value]]
	 * 
	 * // Use for secret reconstruction
	 * const secret = Polynomial.interpolateAtZero(points);
	 * 
	 * @example
	 * // Partial reconstruction with threshold shares
	 * const partialShares = thresholdSigner.secretShares.slice(0, thresholdSigner.requiredSigners);
	 * const thresholdPoints = thresholdSigner.convertSharesToPoints(partialShares);
	 * const reconstructed = Polynomial.interpolateAtZero(thresholdPoints);
	 */
	convertSharesToPoints(shares) {
		if (!Array.isArray(shares) || shares.length === 0) {
			throw new Error('Shares must be a non-empty array');
		}

		return shares.map((share, index) => {
			if (!BN.isBN(share)) {
				throw new Error(`Share at index ${index} must be a BigNumber`);
			}
			return [new BN(index + 1), share]; // 1-based indexing for participants
		});
	}

	/**
	 * Joint Verifiable Random Secret Sharing (JVRSS) protocol implementation
	 * 
	 * JVRSS is the core protocol for distributed key generation without a trusted dealer
	 * as specified in the Nakasendo whitepaper. It combines multiple random polynomials 
	 * from all participants to create a shared secret that no single party knows or can control.
	 * 
	 * **Protocol Steps (Nakasendo Specification):**
	 * 1. **Polynomial Generation**: Each participant conceptually generates a random polynomial
	 * 2. **Share Distribution**: Each polynomial contributes to every participant's final share
	 * 3. **Linear Combination**: Shares are combined additively to create the final distribution
	 * 4. **Public Key Derivation**: The aggregate public key is computed from polynomial constants
	 * 5. **Verification**: Participants can verify the correctness of their shares
	 * 
	 * **Security Properties:**
	 * - No single participant controls the final secret
	 * - The secret is uniformly random over the finite field
	 * - Shares are properly distributed according to Shamir's scheme
	 * - Public key is verifiable and corresponds to the shared secret
	 * - Information-theoretic security guarantees
	 * 
	 * @returns {DistributedKeyGeneration} Key generation result with shares and public key
	 * 
	 * @example
	 * const thresholdSigner = new ThresholdSignature(5, 3);
	 * const keyGen = thresholdSigner.generateJointVerifiableShares();
	 * 
	 * console.log('Secret shares:', keyGen.secretShares.length);        // 5 shares
	 * console.log('Public key type:', keyGen.aggregatePublicKey.constructor.name); // ProjectivePoint
	 * 
	 * // Shares are properly distributed
	 * const points = thresholdSigner.convertSharesToPoints(keyGen.secretShares);
	 * const secret = Polynomial.interpolateAtZero(points);
	 * const derivedPubKey = secp256k1.ProjectivePoint.fromPrivateKey(secret.toBuffer());
	 * 
	 * // Public keys should match
	 * console.log('Keys match:', keyGen.aggregatePublicKey.equals(derivedPubKey)); // true
	 * 
	 * @example
	 * // Understanding the mathematical process
	 * const participantCount = 3, requiredSigners = 2;
	 * const polynomials = Array(participantCount).fill(null)
	 *   .map(() => Polynomial.generateRandom(requiredSigners - 1));
	 * 
	 * // Each participant's share is sum of evaluations from all polynomials
	 * let manualShares = Array(participantCount).fill(new BN(0));
	 * for (let i = 0; i < participantCount; i++) {
	 *   for (let j = 0; j < participantCount; j++) {
	 *     const evaluation = polynomials[i].evaluate(new BN(j + 1));
	 *     manualShares[j] = manualShares[j].add(evaluation.value).umod(CURVE_ORDER);
	 *   }
	 * }
	 * 
	 * // This produces the same mathematical result as JVRSS
	 */
	generateJointVerifiableShares() {
		// Generate random polynomials for each participant
		const polynomials = new Array(this.participantCount)
			.fill(null)
			.map(() => Polynomial.generateRandom(this.polynomialDegree));

		// Initialize shares array with zeros
		let secretShares = new Array(this.participantCount).fill(null).map(() => new BN(0));

		// Combine polynomial evaluations to create final shares
		for (let participantIndex = 0; participantIndex < this.participantCount; participantIndex++) {
			for (let shareIndex = 0; shareIndex < this.participantCount; shareIndex++) {
				const evaluation = polynomials[participantIndex].evaluate(new BN(shareIndex + 1));
				secretShares[shareIndex] = secretShares[shareIndex]
					.add(evaluation.value)
					.umod(CURVE_ORDER);
			}
		}

		// Compute aggregate public key from polynomial constants
		let aggregatePublicKey = secp256k1.ProjectivePoint.ZERO;
		for (let i = 0; i < this.participantCount; i++) {
			const constantTerm = polynomials[i].constantTerm;
			const keyMaterial = constantTerm.toBuffer("be", 32);
			const individualPublicKey = secp256k1.ProjectivePoint.fromPrivateKey(keyMaterial);
			aggregatePublicKey = aggregatePublicKey.add(individualPublicKey);
		}

		return {
			secretShares,
			aggregatePublicKey,
			polynomials
		};
	}

	/**
	 * Additive Secret Sharing (ADDSS) - combines two sets of shares additively
	 * 
	 * ADDSS enables secure addition of two shared secrets without revealing
	 * the individual secrets. Each participant adds their corresponding shares,
	 * and the result can be reconstructed to obtain the sum of the original secrets.
	 * 
	 * **Mathematical Foundation:**
	 * - If secret A is shared as (a₁, a₂, ..., aₙ)
	 * - And secret B is shared as (b₁, b₂, ..., bₙ)  
	 * - Then A + B is shared as (a₁+b₁, a₂+b₂, ..., aₙ+bₙ)
	 * 
	 * **Applications (Nakasendo Specification):**
	 * - Combining multiple randomness sources
	 * - Adding constants to shared secrets
	 * - Building complex cryptographic protocols
	 * - Secure multi-party computation primitives
	 * 
	 * @param {BN[]} firstShareSet - First set of secret shares
	 * @param {BN[]} secondShareSet - Second set of secret shares  
	 * @returns {BN} The sum of the two original secrets
	 * @throws {Error} If share arrays have different lengths or invalid format
	 * 
	 * @example
	 * const thresholdSigner = new ThresholdSignature(3, 2);
	 * 
	 * // Generate two sets of shares using separate key generations
	 * const firstKeyGen = thresholdSigner.generateJointVerifiableShares();
	 * const secondKeyGen = thresholdSigner.generateJointVerifiableShares();
	 * 
	 * // Add the shared secrets
	 * const sum = thresholdSigner.addSecretShares(firstKeyGen.secretShares, secondKeyGen.secretShares);
	 * 
	 * // Verify: sum should equal individual secret sum
	 * const secret1 = thresholdSigner.reconstructSecret(firstKeyGen.secretShares);
	 * const secret2 = thresholdSigner.reconstructSecret(secondKeyGen.secretShares);
	 * const expectedSum = secret1.add(secret2).umod(CURVE_ORDER);
	 * console.log('Addition verified:', sum.eq(expectedSum)); // true
	 * 
	 * @example
	 * // Adding a constant to a shared secret
	 * const constant = new BN(42);
	 * const constantShares = Array(thresholdSigner.participantCount).fill(new BN(0));
	 * constantShares[0] = constant; // Only first share gets the constant
	 * 
	 * const result = thresholdSigner.addSecretShares(thresholdSigner.secretShares, constantShares);
	 * // result = original_secret + 42
	 */
	addSecretShares(firstShareSet, secondShareSet) {
		// Validate input arrays
		if (!Array.isArray(firstShareSet) || !Array.isArray(secondShareSet)) {
			throw new Error('Both share sets must be arrays');
		}

		if (firstShareSet.length !== secondShareSet.length) {
			throw new Error(
				`Share sets must have equal length: ${firstShareSet.length} vs ${secondShareSet.length}`
			);
		}

		if (firstShareSet.length !== this.participantCount) {
			throw new Error(
				`Share set length (${firstShareSet.length}) must match participant count (${this.participantCount})`
			);
		}

		// Perform element-wise addition of shares
		const addedShares = new Array(this.participantCount);
		for (let i = 0; i < this.participantCount; i++) {
			if (!BN.isBN(firstShareSet[i]) || !BN.isBN(secondShareSet[i])) {
				throw new Error(`Shares at index ${i} must be BigNumbers`);
			}
			addedShares[i] = firstShareSet[i].add(secondShareSet[i]).umod(CURVE_ORDER);
		}

		// Reconstruct the sum using random subset of shares
		const sharePoints = this.convertSharesToPoints(addedShares);
		const randomSubset = this.selectRandomSubset(sharePoints, this.requiredSigners);

		return Polynomial.interpolateAtZero(randomSubset);
	}

	/**
	 * Polynomial Reconstruction Secret Sharing (PROSS) - computes product of shared secrets
	 * 
	 * PROSS enables secure multiplication of two shared secrets following the Nakasendo
	 * specification. This is more complex than addition because the product of two 
	 * degree-t polynomials yields a degree-2t polynomial, requiring more shares for reconstruction.
	 * 
	 * **Mathematical Foundation:**
	 * - Product of degree-t polynomials has degree 2t
	 * - Requires 2t+1 shares for reconstruction (vs t+1 for addition)
	 * - Uses polynomial interpolation on the product values
	 * - Result is the product of the original secrets
	 * 
	 * **Security Note:**
	 * - Requires more participants for security than addition
	 * - Product shares reveal more information than additive shares
	 * - Should be used carefully in cryptographic protocols
	 * 
	 * **Applications:**
	 * - Computing multiplicative inverses (used in INVSS)
	 * - Secure polynomial evaluation
	 * - Advanced threshold cryptographic protocols
	 * - Zero-knowledge proof systems
	 * 
	 * @param {BN[]} firstShareSet - First set of secret shares
	 * @param {BN[]} secondShareSet - Second set of secret shares
	 * @returns {BN} The product of the two original secrets
	 * @throws {Error} If insufficient shares for reconstruction or invalid input
	 * 
	 * @example
	 * const thresholdSigner = new ThresholdSignature(5, 2); // Need larger group for PROSS
	 * 
	 * // Generate two secrets
	 * const firstKeyGen = thresholdSigner.generateJointVerifiableShares();
	 * const secondKeyGen = thresholdSigner.generateJointVerifiableShares();
	 * 
	 * // Compute product
	 * const product = thresholdSigner.multiplySecretShares(firstKeyGen.secretShares, secondKeyGen.secretShares);
	 * 
	 * // Verify result
	 * const secret1 = thresholdSigner.reconstructSecret(firstKeyGen.secretShares);
	 * const secret2 = thresholdSigner.reconstructSecret(secondKeyGen.secretShares);
	 * const expectedProduct = secret1.mul(secret2).umod(CURVE_ORDER);
	 * console.log('Multiplication verified:', product.eq(expectedProduct)); // true
	 * 
	 * @example
	 * // Squaring a shared secret
	 * const squared = thresholdSigner.multiplySecretShares(
	 *   thresholdSigner.secretShares, 
	 *   thresholdSigner.secretShares
	 * );
	 * const originalSecret = thresholdSigner.reconstructSecret();
	 * const expectedSquare = originalSecret.mul(originalSecret).umod(CURVE_ORDER);
	 * console.log('Squaring verified:', squared.eq(expectedSquare)); // true
	 */
	multiplySecretShares(firstShareSet, secondShareSet) {
		// Validate input arrays (same validation as addSecretShares)
		if (!Array.isArray(firstShareSet) || !Array.isArray(secondShareSet)) {
			throw new Error('Both share sets must be arrays');
		}

		if (firstShareSet.length !== secondShareSet.length) {
			throw new Error(
				`Share sets must have equal length: ${firstShareSet.length} vs ${secondShareSet.length}`
			);
		}

		if (firstShareSet.length !== this.participantCount) {
			throw new Error(
				`Share set length (${firstShareSet.length}) must match participant count (${this.participantCount})`
			);
		}

		// Check if we have enough shares for degree-2t polynomial reconstruction
		const requiredShares = 2 * this.polynomialDegree + 1;
		if (this.participantCount < requiredShares) {
			throw new Error(
				`Insufficient participants for multiplication: need ${requiredShares}, have ${this.participantCount}`
			);
		}

		// Compute element-wise product of shares
		const multipliedShares = new Array(this.participantCount);
		for (let i = 0; i < this.participantCount; i++) {
			if (!BN.isBN(firstShareSet[i]) || !BN.isBN(secondShareSet[i])) {
				throw new Error(`Shares at index ${i} must be BigNumbers`);
			}
			multipliedShares[i] = firstShareSet[i].mul(secondShareSet[i]).umod(CURVE_ORDER);
		}

		// Reconstruct using 2t+1 shares (product polynomial has degree 2t)
		const sharePoints = this.convertSharesToPoints(multipliedShares);
		const requiredSubset = this.selectRandomSubset(sharePoints, requiredShares);

		return Polynomial.interpolateAtZero(requiredSubset);
	}

	/**
	 * Inverse Secret Sharing (INVSS) - computes modular inverse of shared secret
	 * 
	 * INVSS computes the modular inverse of a shared secret without revealing the secret,
	 * following the Nakasendo specification. This is crucial for threshold ECDSA signatures 
	 * where we need to compute k⁻¹ (inverse of the nonce) as part of the signature generation process.
	 * 
	 * **Algorithm (Nakasendo Protocol):**
	 * 1. Generate a fresh random secret b using JVRSS
	 * 2. Compute c = a × b using PROSS (where a is the input secret)
	 * 3. Reconstruct c (this reveals c but not a or b individually)
	 * 4. Compute c⁻¹ using standard modular inverse
	 * 5. Multiply b shares by c⁻¹ to get shares of a⁻¹
	 * 
	 * **Security:**
	 * - The intermediate value c is revealed but provides no information about a
	 * - The randomness b masks the original secret a
	 * - Final result is properly shared according to the threshold scheme
	 * - Information-theoretic security is maintained
	 * 
	 * @param {BN[]} inputShares - Shares of the secret to invert
	 * @returns {BN[]} Shares of the modular inverse of the original secret
	 * @throws {Error} If input shares are invalid or inversion fails
	 * 
	 * @example
	 * const thresholdSigner = new ThresholdSignature(5, 3);
	 * 
	 * // Compute inverse of shared secret
	 * const inverseShares = thresholdSigner.computeInverseShares(thresholdSigner.secretShares);
	 * 
	 * // Verify: secret × inverse = 1 (mod N)
	 * const product = thresholdSigner.multiplySecretShares(thresholdSigner.secretShares, inverseShares);
	 * console.log('Inverse verified:', product.eq(new BN(1))); // true
	 * 
	 * @example
	 * // Use in threshold signature (simplified)
	 * const message = Buffer.from("Hello World!");
	 * const messageHash = new BN(createHash('sha256').update(message).digest());
	 * 
	 * // Generate nonce shares
	 * const nonceKeyGen = thresholdSigner.generateJointVerifiableShares();
	 * 
	 * // Compute inverse of nonce
	 * const nonceInverseShares = thresholdSigner.computeInverseShares(nonceKeyGen.secretShares);
	 * 
	 * // This would be used in signature computation
	 * // s = k⁻¹(hash + r × private_key)
	 */
	computeInverseShares(inputShares) {
		// Validate input shares
		if (!Array.isArray(inputShares)) {
			throw new Error('Input shares must be an array');
		}

		if (inputShares.length !== this.participantCount) {
			throw new Error(
				`Input shares length (${inputShares.length}) must match participant count (${this.participantCount})`
			);
		}

		for (let i = 0; i < inputShares.length; i++) {
			if (!BN.isBN(inputShares[i])) {
				throw new Error(`Share at index ${i} must be a BigNumber`);
			}
		}

		// Generate fresh randomness b using JVRSS
		const randomnessKeyGen = this.generateJointVerifiableShares();
		const randomnessShares = randomnessKeyGen.secretShares;

		// Compute c = a × b (this will be revealed)
		const productValue = this.multiplySecretShares(inputShares, randomnessShares);

		// Compute modular inverse of c using Fermat's Little Theorem
		// For prime p: a^(-1) = a^(p-2) mod p
		const exponent = CURVE_ORDER.sub(new BN(2));
		const modularInverse = productValue.toRed(BN.red(CURVE_ORDER))
			.redPow(exponent)
			.fromRed();

		// Multiply randomness shares by c⁻¹ to get shares of a⁻¹
		const inverseShares = randomnessShares.map(share =>
			modularInverse.mul(share).umod(CURVE_ORDER)
		);

		return inverseShares;
	}

	/**
	 * Reconstructs the private key from secret shares using polynomial interpolation
	 * 
	 * This method recovers the original private key from the distributed shares.
	 * It should be used with extreme caution as it reconstructs the full private key,
	 * defeating the purpose of the threshold scheme. Typically used only for
	 * specific operations like computing WIF format or for emergency recovery.
	 * 
	 * **Security Warning:**
	 * - Reconstructing the private key centralizes control
	 * - Should only be done when absolutely necessary
	 * - Consider using threshold operations instead when possible
	 * - Ensure secure deletion of reconstructed key after use
	 * 
	 * @param {BN[]} [shareSet] - Secret shares to reconstruct from (defaults to this.secretShares)
	 * @returns {BN} The reconstructed private key as a BigNumber
	 * @throws {Error} If insufficient shares for reconstruction
	 * 
	 * @example
	 * const thresholdSigner = new ThresholdSignature(3, 2);
	 * 
	 * // Reconstruct private key (use with extreme caution!)
	 * console.warn('⚠️  SECURITY WARNING: Reconstructing private key defeats threshold security!');
	 * const privateKey = thresholdSigner.reconstructSecret();
	 * 
	 * // Verify it corresponds to the aggregate public key
	 * const derivedPubKey = secp256k1.ProjectivePoint.fromPrivateKey(privateKey.toBuffer());
	 * console.log('Keys match:', derivedPubKey.equals(thresholdSigner.aggregatePublicKey)); // true
	 * 
	 * @example
	 * // Partial reconstruction with threshold shares only
	 * const thresholdShares = thresholdSigner.secretShares.slice(0, thresholdSigner.requiredSigners);
	 * const partialKey = thresholdSigner.reconstructSecret(thresholdShares);
	 * 
	 * // Should equal full reconstruction
	 * const fullKey = thresholdSigner.reconstructSecret();
	 * console.log('Partial equals full:', partialKey.eq(fullKey)); // true
	 * 
	 * @example
	 * // Emergency recovery scenario
	 * function emergencyRecovery(shareHolders) {
	 *   if (shareHolders.length < thresholdSigner.requiredSigners) {
	 *     throw new Error("Insufficient shares for recovery");
	 *   }
	 *   
	 *   const recoveredKey = thresholdSigner.reconstructSecret(shareHolders.slice(0, thresholdSigner.requiredSigners));
	 *   
	 *   // Use recovered key for emergency operations
	 *   // ... perform emergency actions ...
	 *   
	 *   // Securely delete the key
	 *   recoveredKey.fill(0);
	 * }
	 */
	reconstructSecret(shareSet = null) {
		const sharesToUse = shareSet || this.secretShares;

		if (!Array.isArray(sharesToUse)) {
			throw new Error('Shares must be an array');
		}

		if (sharesToUse.length < this.requiredSigners) {
			throw new Error(
				`Insufficient shares for reconstruction: need ${this.requiredSigners}, have ${sharesToUse.length}`
			);
		}

		const sharePoints = this.convertSharesToPoints(sharesToUse);
		const requiredSubset = sharePoints.slice(0, this.requiredSigners);

		return Polynomial.interpolateAtZero(requiredSubset);
	}

	/**
	 * Generates a threshold signature for a given message
	 * 
	 * This is the core method that produces threshold ECDSA signatures following the
	 * Nakasendo specification. The signature is generated collaboratively using the 
	 * threshold scheme without reconstructing the private key. The process follows 
	 * the threshold ECDSA protocol:
	 * 
	 * **Threshold ECDSA Algorithm (Nakasendo Protocol):**
	 * 1. **Nonce Generation**: Create shared random nonce k using JVRSS
	 * 2. **R Value Computation**: Compute R = k×G and extract r = R.x mod n
	 * 3. **Inverse Computation**: Compute k⁻¹ using INVSS without revealing k
	 * 4. **Signature Shares**: Each party computes their share of s = k⁻¹(hash + r×private)
	 * 5. **Reconstruction**: Combine shares to get final signature (r, s)
	 * 6. **Validation**: Ensure signature is valid and non-zero
	 * 
	 * **Security Properties:**
	 * - Private key never reconstructed during signing
	 * - Nonce is generated distributively and remains secret
	 * - Resulting signature is indistinguishable from single-party ECDSA
	 * - Compatible with standard ECDSA verification
	 * 
	 * @param {string} message - Message to sign (will be SHA256 hashed)
	 * @returns {ThresholdSignatureResult} Complete signature with metadata
	 * @throws {Error} If signature generation fails
	 * 
	 * @example
	 * const thresholdSigner = new ThresholdSignature(3, 2);
	 * 
	 * // Generate threshold signature
	 * const signature = thresholdSigner.sign("Transfer $1000 to Alice");
	 * 
	 * console.log('r value:', signature.signature.r);           // BigInt r value
	 * console.log('s value:', signature.signature.s);           // BigInt s value  
	 * console.log('Serialized:', signature.serializedSignature); // Base64 compact format
	 * console.log('Recovery ID:', signature.recoveryId);         // 0-3 for public key recovery
	 * 
	 * // Verify signature
	 * const isValid = ThresholdSignature.verifyThresholdSignature(
	 *   thresholdSigner.aggregatePublicKey,
	 *   signature.messageHash,
	 *   signature.signature
	 * );
	 * console.log('Signature valid:', isValid); // true
	 * 
	 * @example
	 * // Corporate authorization workflow
	 * const corporateThresholdSigner = new ThresholdSignature(5, 3);
	 * 
	 * const authMessage = JSON.stringify({
	 *   action: "wire_transfer",
	 *   amount: 1000000,
	 *   recipient: "operations_account",
	 *   timestamp: Date.now()
	 * });
	 * 
	 * const authorization = corporateThresholdSigner.sign(authMessage);
	 * console.log("Authorization signature:", authorization.serializedSignature);
	 * 
	 * @example
	 * // Escrow release with buyer + seller
	 * const escrowThresholdSigner = new ThresholdSignature(3, 2);
	 * 
	 * const releaseMessage = "Release escrow funds to seller";
	 * const escrowSignature = escrowThresholdSigner.sign(releaseMessage);
	 * 
	 * // This signature can be verified by anyone
	 * const verified = ThresholdSignature.verifyThresholdSignature(
	 *   escrowThresholdSigner.aggregatePublicKey,
	 *   escrowSignature.messageHash,
	 *   escrowSignature.signature
	 * );
	 */
	sign(message) {
		if (!message || typeof message !== 'string') {
			throw new Error('Message must be a non-empty string');
		}

		// Hash the message using SHA256
		const messageHash = new BN(createHash('sha256').update(Buffer.from(message)).digest());
		let [recoveryId, rValue, sValue] = [0, 0, 0];

		// Retry until we get a valid signature
		while (!sValue) {
			let nonceInverseShares = [];

			// Generate nonce and retry until we get valid r
			while (!rValue) {
				// Generate distributed nonce k using JVRSS
				const nonceKeyGeneration = this.generateJointVerifiableShares();
				const nonceShares = nonceKeyGeneration.secretShares;
				const noncePublicKey = nonceKeyGeneration.aggregatePublicKey;

				const [noncePointX, noncePointY] = [new BN(noncePublicKey.x), new BN(noncePublicKey.y)];
				rValue = noncePointX.umod(CURVE_ORDER);

				// Compute recovery ID for public key recovery
				recoveryId = (noncePointX.gt(CURVE_ORDER) ? 2 : 0) | (noncePointY.modrn(2));

				// Compute inverse of nonce for signature
				if (rValue.gt(new BN(0))) {
					nonceInverseShares = this.computeInverseShares(nonceShares);
				}
			}

			// Compute signature shares: s_i = k⁻¹(hash + r × private_key_i)
			const signatureShares = new Array(this.participantCount);
			for (let i = 0; i < this.participantCount; i++) {
				const hashPlusRTimesPrivateKey = rValue.mul(this.secretShares[i]).add(messageHash).umod(CURVE_ORDER);
				signatureShares[i] = hashPlusRTimesPrivateKey.mul(nonceInverseShares[i]).umod(CURVE_ORDER);
			}

			// Reconstruct final s value
			const signatureSharePoints = this.convertSharesToPoints(signatureShares);
			const requiredSubset = this.selectRandomSubset(signatureSharePoints, this.requiredSigners);
			sValue = Polynomial.interpolateAtZero(requiredSubset);

			// Ensure s is not zero
			if (sValue.isZero()) {
				sValue = 0; // Reset to retry
				rValue = 0;
			}
		}

		// Convert to standard format
		const rBuffer = rValue.toBuffer();
		const sBuffer = sValue.toBuffer();

		// Create recovery prefix for serialized signature
		const recoveryPrefix = new BN(27 + recoveryId + 4).toBuffer();
		const serializedSignature = Buffer.concat([recoveryPrefix, rBuffer, sBuffer]).toString('base64');

		// Create signature object
		const signatureObject = secp256k1.Signature.fromCompact(Buffer.concat([rBuffer, sBuffer]));

		return {
			signature: signatureObject,
			serializedSignature,
			messageHash: messageHash.toBuffer(),
			recoveryId
		};
	}

	/**
	 * Verifies a threshold signature against a public key and message hash
	 * 
	 * This static method verifies threshold signatures using standard ECDSA verification
	 * following the Nakasendo specification. Threshold signatures are indistinguishable 
	 * from regular ECDSA signatures, so standard verification algorithms work without modification.
	 * 
	 * **Verification Algorithm:**
	 * 1. **Input Validation**: Ensure signature components r and s are valid
	 * 2. **Hash Processing**: Use the provided message hash (already computed)
	 * 3. **Inverse Computation**: Compute w = s⁻¹ mod n
	 * 4. **Point Calculation**: Compute u₁ = w×hash and u₂ = w×r
	 * 5. **Point Addition**: Compute point = u₁×G + u₂×PublicKey
	 * 6. **Verification**: Check if point.x ≡ r (mod n)
	 * 
	 * **Compatibility:**
	 * - Works with any ECDSA signature, threshold or single-party
	 * - Uses standard secp256k1 curve parameters
	 * - Compatible with Bitcoin and Ethereum signature formats
	 * - Can be used by third parties without threshold scheme knowledge
	 * 
	 * @static
	 * @param {Object} aggregatePublicKey - Elliptic curve public key point
	 * @param {Buffer} messageHash - SHA256 hash of the original message
	 * @param {Object} signature - Signature object with r and s components
	 * @param {bigint} signature.r - Signature r value
	 * @param {bigint} signature.s - Signature s value
	 * @returns {boolean} True if signature is valid, false otherwise
	 * 
	 * @example
	 * // Verify a threshold signature
	 * const thresholdSigner = new ThresholdSignature(3, 2);
	 * const signature = thresholdSigner.sign("Hello World!");
	 * 
	 * const isValid = ThresholdSignature.verifyThresholdSignature(
	 *   thresholdSigner.aggregatePublicKey,
	 *   signature.messageHash,
	 *   signature.signature
	 * );
	 * console.log('Signature valid:', isValid); // true
	 * 
	 * @example
	 * // Third-party verification (doesn't need threshold scheme)
	 * function verifyTransaction(publicKey, messageHash, signature) {
	 *   return ThresholdSignature.verifyThresholdSignature(
	 *     publicKey,
	 *     messageHash,
	 *     signature
	 *   );
	 * }
	 * 
	 * // Works with any ECDSA signature
	 * const valid = verifyTransaction(
	 *   somePublicKey,
	 *   someMessageHash,
	 *   someSignature
	 * );
	 * 
	 * @example
	 * // Batch verification for multiple signatures
	 * function verifyBatch(signatures) {
	 *   return signatures.every(({ publicKey, msgHash, sig }) =>
	 *     ThresholdSignature.verifyThresholdSignature(publicKey, msgHash, sig)
	 *   );
	 * }
	 * 
	 * @example
	 * // Integration with Bitcoin transaction verification
	 * function verifyBitcoinTransaction(transaction, publicKey) {
	 *   const messageHash = computeTransactionHash(transaction);
	 *   const signature = extractSignature(transaction);
	 *   
	 *   return ThresholdSignature.verifyThresholdSignature(
	 *     publicKey,
	 *     messageHash,
	 *     signature
	 *   );
	 * }
	 */
	static verifyThresholdSignature(aggregatePublicKey, messageHash, signature) {
		try {
			// Validate inputs
			if (!aggregatePublicKey || typeof aggregatePublicKey.x === 'undefined') {
				throw new Error('Invalid public key format');
			}

			if (!Buffer.isBuffer(messageHash) || messageHash.length !== 32) {
				throw new Error('Message hash must be a 32-byte Buffer');
			}

			if (!signature || typeof signature.r === 'undefined' || typeof signature.s === 'undefined') {
				throw new Error('Invalid signature format');
			}

			const messageHashBN = new BN(messageHash);

			// Compute modular inverse of s using Fermat's Little Theorem
			const sBN = new BN(signature.s.toString());
			const exponent = CURVE_ORDER.sub(new BN(2));
			const sInverse = sBN.toRed(BN.red(CURVE_ORDER)).redPow(exponent).fromRed();

			// Compute verification values
			const u1 = sInverse.mul(messageHashBN).umod(CURVE_ORDER).toBuffer('be', 32);
			const u2 = sInverse.mul(new BN(signature.r.toString())).umod(CURVE_ORDER).toBuffer('be', 32);

			// Compute verification point: u1*G + u2*PublicKey
			const verificationPoint = secp256k1.ProjectivePoint.fromPrivateKey(u1)
				.add(aggregatePublicKey.multiply(bufToBigint(u2)));

			// Verify that point.x equals signature.r
			return signature.r === (verificationPoint.x % secp256k1.CURVE.n);

		} catch (error) {
			// Log error for debugging but return false for verification failure
			console.error('Signature verification error:', error.message);
			return false;
		}
	}

	/**
	 * Selects a random subset of points for interpolation
	 * 
	 * @private
	 * @param {SharePoints} points - Array of coordinate points
	 * @param {number} count - Number of points to select
	 * @returns {SharePoints} Random subset of points
	 */
	selectRandomSubset(points, count) {
		if (points.length < count) {
			throw new Error(`Insufficient points: need ${count}, have ${points.length}`);
		}

		// Create a copy and randomly shuffle
		const shuffled = [...points].sort(() => 0.5 - Math.random());
		return shuffled.slice(0, count);
	}

	/**
	 * Gets a summary of the threshold scheme configuration
	 * 
	 * @returns {Object} Scheme summary information
	 */
	getSchemeSummary() {
		return {
			participantCount: this.participantCount,
			requiredSigners: this.requiredSigners,
			polynomialDegree: this.polynomialDegree,
			schemeId: this.schemeId,
			securityLevel: this.requiredSigners >= this.participantCount * 0.6 ? 'High' :
				this.requiredSigners >= this.participantCount * 0.4 ? 'Medium' : 'Low'
		};
	}
}

export default ThresholdSignature;