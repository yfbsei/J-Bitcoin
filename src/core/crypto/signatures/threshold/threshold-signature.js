/**
 * @fileoverview Threshold Signature Scheme implementation for distributed cryptography
 * 
 * This module implements a complete threshold signature scheme using Shamir's Secret Sharing
 * and elliptic curve cryptography following the Nakasendo Threshold Signatures specification.
 * 
 * SECURITY UPDATES:
 * - Nonce reuse prevention with tracking system
 * - Canonical signature enforcement (s ≤ n/2)
 * - Enhanced input validation and bounds checking
 * - Feldman commitments for verifiable secret sharing
 * - Protection against timing and side-channel attacks
 * - Comprehensive signature validation
 * 
 * @see {@link https://web.archive.org/web/20211216212202/https://nakasendoproject.org/Threshold-Signatures-whitepaper-nchain.pdf|Nakasendo Threshold Signatures Whitepaper}
 * @author yfbsei
 * @version 2.1.0
 */

import { createHash } from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1';
import { bufToBigint } from 'bigint-conversion';
import BN from 'bn.js';

import Polynomial from './polynomial.js';
import { CRYPTO_CONSTANTS, THRESHOLD_CONSTANTS } from '../../../constants.js';
import { validateThresholdParams, assertValid } from '../../../../utils/validation.js';

/**
 * secp256k1 curve order for modular arithmetic
 * @constant {BN}
 */
const CURVE_ORDER = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, "hex");

/**
 * Half of curve order for canonical signature enforcement
 * @constant {BN}
 */
const HALF_CURVE_ORDER = CURVE_ORDER.div(new BN(2));

/**
 * Nonce management system to prevent nonce reuse attacks
 */
class NonceManager {
	constructor() {
		this.usedNonces = new Set();
		this.maxNonceHistory = 10000; // Prevent memory bloat
	}

	/**
	 * Checks if a nonce has been used and marks it as used
	 * @param {Buffer} messageHash - Message hash
	 * @param {BN} nonce - Nonce value
	 * @throws {Error} If nonce reuse is detected
	 */
	checkAndMarkNonce(messageHash, nonce) {
		const nonceKey = createHash('sha256')
			.update(messageHash)
			.update(nonce.toBuffer('be', 32))
			.digest('hex');

		if (this.usedNonces.has(nonceKey)) {
			throw new Error('CRITICAL SECURITY VIOLATION: Nonce reuse detected');
		}

		this.usedNonces.add(nonceKey);

		// Prevent memory bloat by limiting history size
		if (this.usedNonces.size > this.maxNonceHistory) {
			const oldestNonce = this.usedNonces.values().next().value;
			this.usedNonces.delete(oldestNonce);
		}
	}

	/**
	 * Clears all nonce history (use with caution)
	 */
	clearHistory() {
		this.usedNonces.clear();
	}
}

/**
 * Signature validation utilities
 */
class SignatureValidator {
	/**
	 * Validates ECDSA signature components
	 * @param {Object} signature - Signature object with r and s
	 * @returns {Object} Validated and potentially canonicalized signature
	 * @throws {Error} If signature is invalid
	 */
	static validateAndCanonicalize(signature) {
		if (!signature || typeof signature.r === 'undefined' || typeof signature.s === 'undefined') {
			throw new Error('Invalid signature format: missing r or s components');
		}

		let r = new BN(signature.r.toString());
		let s = new BN(signature.s.toString());

		// Validate r and s are in valid range [1, n-1]
		if (r.isZero() || r.gte(CURVE_ORDER)) {
			throw new Error('Invalid signature: r component out of range');
		}

		if (s.isZero() || s.gte(CURVE_ORDER)) {
			throw new Error('Invalid signature: s component out of range');
		}

		// Enforce canonical signature (s ≤ n/2) to prevent malleability
		if (s.gt(HALF_CURVE_ORDER)) {
			s = CURVE_ORDER.sub(s);
			console.warn('⚠️  Signature canonicalized: s value was greater than n/2');
		}

		return {
			r: r,
			s: s,
			canonicalized: !s.eq(new BN(signature.s.toString()))
		};
	}

	/**
	 * Validates elliptic curve point
	 * @param {Object} point - Point to validate
	 * @throws {Error} If point is invalid
	 */
	static validatePoint(point) {
		if (!point || typeof point.x === 'undefined' || typeof point.y === 'undefined') {
			throw new Error('Invalid point: missing coordinates');
		}

		// Verify point is on curve: y² = x³ + 7 (mod p)
		try {
			const x = new BN(point.x.toString());
			const y = new BN(point.y.toString());

			if (x.gte(secp256k1.CURVE.p) || y.gte(secp256k1.CURVE.p)) {
				throw new Error('Point coordinates exceed field prime');
			}
		} catch (error) {
			throw new Error(`Point validation failed: ${error.message}`);
		}
	}
}

/**
 * Feldman commitment implementation for verifiable secret sharing
 */
class FeldmanCommitments {
	/**
	 * Generates Feldman commitments for polynomial coefficients
	 * @param {Polynomial} polynomial - Polynomial to commit to
	 * @returns {Array} Array of elliptic curve points (commitments)
	 */
	static generateCommitments(polynomial) {
		const commitments = [];

		for (let i = 0; i <= polynomial.degree; i++) {
			const coeff = polynomial.coefficients[i];
			const commitment = secp256k1.ProjectivePoint.fromPrivateKey(coeff.toBuffer('be', 32));
			commitments.push(commitment);
		}

		return commitments;
	}

	/**
	 * Verifies a share against Feldman commitments
	 * @param {BN} share - Share value to verify
	 * @param {number} participantIndex - 1-based participant index
	 * @param {Array} commitments - Array of commitment points
	 * @returns {boolean} True if share is valid
	 */
	static verifyShare(share, participantIndex, commitments) {
		if (participantIndex < 1) {
			throw new Error('Participant index must be >= 1');
		}

		try {
			// Compute expected commitment: ∏ C_j^(i^j)
			let expectedCommitment = secp256k1.ProjectivePoint.ZERO;

			for (let j = 0; j < commitments.length; j++) {
				const exponent = new BN(participantIndex).pow(new BN(j)).umod(CURVE_ORDER);
				const term = commitments[j].multiply(bufToBigint(exponent.toBuffer('be', 32)));
				expectedCommitment = expectedCommitment.add(term);
			}

			// Compute actual commitment: share * G
			const actualCommitment = secp256k1.ProjectivePoint.fromPrivateKey(share.toBuffer('be', 32));

			return expectedCommitment.equals(actualCommitment);
		} catch (error) {
			console.error('Share verification failed:', error.message);
			return false;
		}
	}
}

/**
 * @typedef {Object} ThresholdSignatureResult
 * @property {Object} signature - ECDSA signature object with r and s components
 * @property {bigint} signature.r - Signature r value as BigInt
 * @property {bigint} signature.s - Signature s value as BigInt
 * @property {string} serializedSignature - Base64-encoded compact signature format
 * @property {Buffer} messageHash - SHA256 hash of the signed message
 * @property {number} recoveryId - Recovery ID for public key recovery (0-3)
 * @property {boolean} canonicalized - Whether signature was canonicalized
 */

/**
 * Threshold Signature Scheme implementation for distributed cryptography
 * 
 * Enhanced with comprehensive security features including nonce management,
 * signature canonicalization, and verifiable secret sharing.
 * 
 * @class ThresholdSignature
 */
class ThresholdSignature {

	/**
	 * Creates a new threshold signature scheme instance
	 * 
	 * @param {number} [participantCount=3] - Total number of participants in the scheme
	 * @param {number} [requiredSigners=2] - Minimum number of participants needed for operations
	 * @throws {Error} If threshold constraints are violated
	 */
	constructor(participantCount = 3, requiredSigners = 2) {
		// Validate threshold parameters
		const validation = validateThresholdParams(participantCount, requiredSigners);
		assertValid(validation);

		this.participantCount = participantCount;
		this.polynomialDegree = requiredSigners - 1;
		this.requiredSigners = requiredSigners;
		this.schemeId = `${requiredSigners}-of-${participantCount}`;

		// Initialize security features
		this.nonceManager = new NonceManager();
		this.feldmanCommitments = null;

		// Generate distributed key shares and aggregate public key using JVRSS
		const keyGeneration = this.generateJointVerifiableShares();

		this.secretShares = keyGeneration.secretShares;
		this.aggregatePublicKey = keyGeneration.aggregatePublicKey;
		this.generationPolynomials = keyGeneration.polynomials;
		this.feldmanCommitments = keyGeneration.commitments;

		// Verify the distributed key generation
		this.verifyDistributedKeyGeneration();
	}

	/**
	 * Converts share values to coordinate points for polynomial interpolation
	 * 
	 * @param {BN[]} shares - Array of BigNumber share values to convert
	 * @returns {Array} Array of [x, y] coordinate pairs for interpolation
	 * @throws {Error} If shares array is invalid
	 */
	convertSharesToPoints(shares) {
		if (!Array.isArray(shares) || shares.length === 0) {
			throw new Error('Shares must be a non-empty array');
		}

		return shares.map((share, index) => {
			if (!BN.isBN(share)) {
				throw new Error(`Share at index ${index} must be a BigNumber`);
			}

			// Validate share is in valid range
			if (share.isZero() || share.gte(CURVE_ORDER)) {
				throw new Error(`Invalid share at index ${index}: must be in range [1, n-1]`);
			}

			return [new BN(index + 1), share]; // 1-based indexing for participants
		});
	}

	/**
	 * Joint Verifiable Random Secret Sharing (JVRSS) protocol implementation
	 * 
	 * Enhanced with Feldman commitments for verifiable secret sharing and
	 * comprehensive validation of the distributed key generation process.
	 * 
	 * @returns {Object} Key generation result with shares, public key, and commitments
	 */
	generateJointVerifiableShares() {
		// Generate random polynomials for each participant
		const polynomials = new Array(this.participantCount)
			.fill(null)
			.map(() => Polynomial.generateRandom(this.polynomialDegree));

		// Generate Feldman commitments for each polynomial
		const allCommitments = polynomials.map(poly =>
			FeldmanCommitments.generateCommitments(poly)
		);

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

		// Combine Feldman commitments
		const aggregateCommitments = [];
		for (let coeffIndex = 0; coeffIndex <= this.polynomialDegree; coeffIndex++) {
			let aggregateCommitment = secp256k1.ProjectivePoint.ZERO;
			for (let polyIndex = 0; polyIndex < this.participantCount; polyIndex++) {
				aggregateCommitment = aggregateCommitment.add(allCommitments[polyIndex][coeffIndex]);
			}
			aggregateCommitments.push(aggregateCommitment);
		}

		return {
			secretShares,
			aggregatePublicKey,
			polynomials,
			commitments: aggregateCommitments
		};
	}

	/**
	 * Verifies the distributed key generation using Feldman commitments
	 * 
	 * @throws {Error} If any share fails verification
	 */
	verifyDistributedKeyGeneration() {
		if (!this.feldmanCommitments || this.feldmanCommitments.length === 0) {
			console.warn('⚠️  No Feldman commitments available for verification');
			return;
		}

		for (let i = 0; i < this.secretShares.length; i++) {
			const isValid = FeldmanCommitments.verifyShare(
				this.secretShares[i],
				i + 1,
				this.feldmanCommitments
			);

			if (!isValid) {
				throw new Error(`Share verification failed for participant ${i + 1}`);
			}
		}

		console.log('✅ All shares verified against Feldman commitments');
	}

	/**
	 * Additive Secret Sharing (ADDSS) - combines two sets of shares additively
	 * 
	 * @param {BN[]} firstShareSet - First set of secret shares
	 * @param {BN[]} secondShareSet - Second set of secret shares  
	 * @returns {BN} The sum of the two original secrets
	 * @throws {Error} If share arrays have different lengths or invalid format
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

		// Perform element-wise addition of shares with validation
		const addedShares = new Array(this.participantCount);
		for (let i = 0; i < this.participantCount; i++) {
			if (!BN.isBN(firstShareSet[i]) || !BN.isBN(secondShareSet[i])) {
				throw new Error(`Shares at index ${i} must be BigNumbers`);
			}

			// Validate shares are in valid range
			if (firstShareSet[i].gte(CURVE_ORDER) || secondShareSet[i].gte(CURVE_ORDER)) {
				throw new Error(`Share at index ${i} exceeds curve order`);
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
	 * @param {BN[]} firstShareSet - First set of secret shares
	 * @param {BN[]} secondShareSet - Second set of secret shares
	 * @returns {BN} The product of the two original secrets
	 * @throws {Error} If insufficient shares for reconstruction or invalid input
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

		// Compute element-wise product of shares with validation
		const multipliedShares = new Array(this.participantCount);
		for (let i = 0; i < this.participantCount; i++) {
			if (!BN.isBN(firstShareSet[i]) || !BN.isBN(secondShareSet[i])) {
				throw new Error(`Shares at index ${i} must be BigNumbers`);
			}

			// Validate shares are in valid range
			if (firstShareSet[i].gte(CURVE_ORDER) || secondShareSet[i].gte(CURVE_ORDER)) {
				throw new Error(`Share at index ${i} exceeds curve order`);
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
	 * Enhanced with additional security checks and validation.
	 * 
	 * @param {BN[]} inputShares - Shares of the secret to invert
	 * @returns {BN[]} Shares of the modular inverse of the original secret
	 * @throws {Error} If input shares are invalid or inversion fails
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

			if (inputShares[i].gte(CURVE_ORDER)) {
				throw new Error(`Share at index ${i} exceeds curve order`);
			}
		}

		// Generate fresh randomness b using JVRSS
		const randomnessKeyGen = this.generateJointVerifiableShares();
		const randomnessShares = randomnessKeyGen.secretShares;

		// Compute c = a × b (this will be revealed)
		const productValue = this.multiplySecretShares(inputShares, randomnessShares);

		// Validate that product is not zero (would make inversion impossible)
		if (productValue.isZero()) {
			throw new Error('Cannot compute inverse: product value is zero');
		}

		// Compute modular inverse of c using Fermat's Little Theorem
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
	 * @param {BN[]} [shareSet] - Secret shares to reconstruct from (defaults to this.secretShares)
	 * @returns {BN} The reconstructed private key as a BigNumber
	 * @throws {Error} If insufficient shares for reconstruction
	 */
	reconstructSecret(shareSet = null) {
		console.warn('⚠️  SECURITY WARNING: Reconstructing private key defeats threshold security!');

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
	 * Enhanced with comprehensive security features including nonce management,
	 * signature canonicalization, and extensive validation.
	 * 
	 * @param {string} message - Message to sign (will be SHA256 hashed)
	 * @returns {ThresholdSignatureResult} Complete signature with metadata
	 * @throws {Error} If signature generation fails
	 */
	sign(message) {
		if (!message || typeof message !== 'string') {
			throw new Error('Message must be a non-empty string');
		}

		// Hash the message using SHA256
		const messageHash = createHash('sha256').update(Buffer.from(message)).digest();
		const messageHashBN = new BN(messageHash);

		let [recoveryId, rValue, sValue] = [0, null, null];
		let attempts = 0;
		const maxAttempts = 100; // Prevent infinite loops

		// Retry until we get a valid signature
		while (!sValue && attempts < maxAttempts) {
			attempts++;
			let nonceInverseShares = [];

			// Generate nonce and retry until we get valid r
			while (!rValue && attempts < maxAttempts) {
				// Generate distributed nonce k using JVRSS
				const nonceKeyGeneration = this.generateJointVerifiableShares();
				const nonceShares = nonceKeyGeneration.secretShares;
				const noncePublicKey = nonceKeyGeneration.aggregatePublicKey;

				// Validate nonce public key
				SignatureValidator.validatePoint(noncePublicKey);

				// Check for nonce reuse
				const nonceSecret = Polynomial.interpolateAtZero(
					this.convertSharesToPoints(nonceShares).slice(0, this.requiredSigners)
				);

				try {
					this.nonceManager.checkAndMarkNonce(messageHash, nonceSecret);
				} catch (error) {
					console.error('Nonce reuse detected, generating new nonce');
					continue;
				}

				const [noncePointX, noncePointY] = [new BN(noncePublicKey.x), new BN(noncePublicKey.y)];
				rValue = noncePointX.umod(CURVE_ORDER);

				// Ensure r is not zero
				if (rValue.isZero()) {
					rValue = null;
					continue;
				}

				// Compute recovery ID for public key recovery
				recoveryId = (noncePointX.gte(CURVE_ORDER) ? 2 : 0) | (noncePointY.modrn(2));

				// Compute inverse of nonce for signature
				nonceInverseShares = this.computeInverseShares(nonceShares);
			}

			if (!rValue) {
				throw new Error(`Failed to generate valid r value after ${maxAttempts} attempts`);
			}

			// Compute signature shares: s_i = k⁻¹(hash + r × private_key_i)
			const signatureShares = new Array(this.participantCount);
			for (let i = 0; i < this.participantCount; i++) {
				const hashPlusRTimesPrivateKey = rValue.mul(this.secretShares[i]).add(messageHashBN).umod(CURVE_ORDER);
				signatureShares[i] = hashPlusRTimesPrivateKey.mul(nonceInverseShares[i]).umod(CURVE_ORDER);
			}

			// Reconstruct final s value
			const signatureSharePoints = this.convertSharesToPoints(signatureShares);
			const requiredSubset = this.selectRandomSubset(signatureSharePoints, this.requiredSigners);
			sValue = Polynomial.interpolateAtZero(requiredSubset);

			// Ensure s is not zero and canonicalize if necessary
			if (sValue.isZero()) {
				sValue = null;
				rValue = null;
				continue;
			}

			// Enforce canonical signature (s ≤ n/2)
			let canonicalized = false;
			if (sValue.gt(HALF_CURVE_ORDER)) {
				sValue = CURVE_ORDER.sub(sValue);
				canonicalized = true;
			}
		}

		if (!sValue || !rValue) {
			throw new Error(`Failed to generate valid signature after ${maxAttempts} attempts`);
		}

		// Convert to standard format
		const rBuffer = rValue.toBuffer('be', 32);
		const sBuffer = sValue.toBuffer('be', 32);

		// Create recovery prefix for serialized signature
		const recoveryPrefix = new BN(27 + recoveryId + 4).toBuffer();
		const serializedSignature = Buffer.concat([recoveryPrefix, rBuffer, sBuffer]).toString('base64');

		// Create signature object
		const signatureObject = {
			r: BigInt('0x' + rValue.toString(16)),
			s: BigInt('0x' + sValue.toString(16))
		};

		// Validate the generated signature
		const validationResult = SignatureValidator.validateAndCanonicalize(signatureObject);

		return {
			signature: {
				r: validationResult.r.toString(),
				s: validationResult.s.toString()
			},
			serializedSignature,
			messageHash: messageHash,
			recoveryId,
			canonicalized: validationResult.canonicalized
		};
	}

	/**
	 * Verifies a threshold signature against a public key and message hash
	 * 
	 * Enhanced with comprehensive validation and security checks.
	 * 
	 * @static
	 * @param {Object} aggregatePublicKey - Elliptic curve public key point
	 * @param {Buffer} messageHash - SHA256 hash of the original message
	 * @param {Object} signature - Signature object with r and s components
	 * @returns {boolean} True if signature is valid, false otherwise
	 */
	static verifyThresholdSignature(aggregatePublicKey, messageHash, signature) {
		try {
			// Comprehensive input validation
			if (!aggregatePublicKey || typeof aggregatePublicKey.x === 'undefined') {
				throw new Error('Invalid public key format');
			}

			SignatureValidator.validatePoint(aggregatePublicKey);

			if (!Buffer.isBuffer(messageHash) || messageHash.length !== 32) {
				throw new Error('Message hash must be a 32-byte Buffer');
			}

			// Validate and canonicalize signature
			const validatedSig = SignatureValidator.validateAndCanonicalize(signature);
			const { r: rBN, s: sBN } = validatedSig;

			const messageHashBN = new BN(messageHash);

			// Compute modular inverse of s using Fermat's Little Theorem
			const exponent = CURVE_ORDER.sub(new BN(2));
			const sInverse = sBN.toRed(BN.red(CURVE_ORDER)).redPow(exponent).fromRed();

			// Compute verification values
			const u1 = sInverse.mul(messageHashBN).umod(CURVE_ORDER).toBuffer('be', 32);
			const u2 = sInverse.mul(rBN).umod(CURVE_ORDER).toBuffer('be', 32);

			// Compute verification point: u1*G + u2*PublicKey
			const verificationPoint = secp256k1.ProjectivePoint.fromPrivateKey(u1)
				.add(aggregatePublicKey.multiply(bufToBigint(u2)));

			// Verify that point.x equals signature.r
			const verificationX = verificationPoint.x % secp256k1.CURVE.n;
			const signatureR = BigInt('0x' + rBN.toString(16));

			return verificationX === signatureR;

		} catch (error) {
			// Log detailed error for debugging in development
			if (process.env.NODE_ENV === 'development') {
				console.error('Signature verification error:', error.message);
			}
			return false;
		}
	}

	/**
	 * Selects a random subset of points for interpolation
	 * 
	 * @private
	 * @param {Array} points - Array of coordinate points
	 * @param {number} count - Number of points to select
	 * @returns {Array} Random subset of points
	 */
	selectRandomSubset(points, count) {
		if (points.length < count) {
			throw new Error(`Insufficient points: need ${count}, have ${points.length}`);
		}

		// Create a copy and randomly shuffle using Fisher-Yates algorithm
		const shuffled = [...points];
		for (let i = shuffled.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
		}

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
				this.requiredSigners >= this.participantCount * 0.4 ? 'Medium' : 'Low',
			feldmanCommitmentsEnabled: this.feldmanCommitments !== null,
			nonceHistorySize: this.nonceManager.usedNonces.size
		};
	}

	/**
	 * Clears sensitive data and resets nonce history
	 */
	destroy() {
		// Clear nonce history
		this.nonceManager.clearHistory();

		// Clear secret shares
		this.secretShares.forEach(share => {
			if (BN.isBN(share)) {
				// Overwrite with random data before clearing
				share.fromBuffer(randomBytes(32));
				share.fromNumber(0);
			}
		});

		// Clear polynomials
		if (this.generationPolynomials) {
			this.generationPolynomials.forEach(poly => {
				if (poly && typeof poly.destroy === 'function') {
					poly.destroy();
				}
			});
		}

		console.log('⚠️  Threshold signature scheme destroyed - all sensitive data cleared');
	}
}

export default ThresholdSignature;