/**
 * @fileoverview Threshold Signature Scheme (TSS) implementation for distributed cryptographic signatures
 * 
 * This module implements a threshold signature scheme that allows a group of participants
 * to collectively generate signatures without any single party having access to the complete
 * private key. It uses Shamir's Secret Sharing and polynomial interpolation to distribute
 * key material and reconstruct signatures.
 * 
 * @see {@link https://en.wikipedia.org/wiki/Threshold_cryptosystem|Threshold Cryptosystem}
 * @see {@link https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing|Shamir's Secret Sharing}
 * @author yfbsei
 * @version 1.0.0
 */

import Polynomial from "./Polynomial.js";
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from "bn.js";
import { createHash } from 'node:crypto';
import { bufToBigint } from 'bigint-conversion';

// secp256k1 curve order for modular arithmetic
const N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", "hex");

/**
 * @typedef {Object} ThresholdSignatureResult
 * @property {Signature} sig - ECDSA signature object with r and s values
 * @property {string} serialized_sig - Base64-encoded compact signature format
 * @property {Buffer} msgHash - SHA256 hash of the signed message
 * @property {number} recovery_id - Recovery ID for public key recovery (0-3)
 */

/**
 * @typedef {Array<Array<number>>} SharePoints
 * @description Array of [x, y] coordinate pairs representing polynomial evaluation points
 * @example [[1, share1], [2, share2], [3, share3]]
 */

/**
 * Threshold Signature Scheme implementation for distributed cryptography
 * 
 * This class enables multiple parties to collectively control a private key and generate
 * signatures without any single party knowing the complete key. It implements:
 * - Joint Verifiable Random Secret Sharing (JVRSS) for key generation
 * - Additive Secret Sharing (ADDSS) for combining shares
 * - Multiplicative Secret Sharing (PROSS) for share products
 * - Inverse Secret Sharing (INVSS) for modular inverses
 * 
 * @class ThresholdSignature
 * @example
 * // Create a 2-of-3 threshold signature scheme
 * const tss = new ThresholdSignature(3, 2);
 * 
 * // Get the generated shares and public key
 * const shares = tss.shares;
 * const publicKey = tss.public_key;
 * 
 * // Generate a threshold signature
 * const signature = tss.sign("Hello Threshold World!");
 * 
 * // Verify the signature
 * const isValid = ThresholdSignature.verify_threshold_signature(
 *   publicKey, signature.msgHash, signature.sig
 * );
 */
class ThresholdSignature {

	/**
	 * Creates a new threshold signature scheme
	 * 
	 * Initializes the scheme by generating polynomial shares for all participants
	 * and computing the corresponding public key through JVRSS protocol.
	 * 
	 * @param {number} [group_size=3] - Total number of participants in the scheme
	 * @param {number} [threshold=2] - Minimum number of participants needed to create signatures
	 * @throws {Error} If threshold is less than 1 or greater than group_size
	 * @example
	 * // Create a 3-of-5 scheme (any 3 out of 5 can sign)
	 * const tss = new ThresholdSignature(5, 3);
	 * 
	 * // Create a 2-of-2 scheme (both parties must participate)
	 * const multisig = new ThresholdSignature(2, 2);
	 */
	constructor(group_size = 3, threshold = 2) {
		/**
		 * Total number of participants
		 * @type {number}
		 * @readonly
		 */
		this.group_size = group_size;

		/**
		 * Polynomial degree (threshold - 1)
		 * @type {number}
		 * @readonly
		 */
		this.polynomial_order = threshold - 1;

		/**
		 * Minimum participants needed for operations
		 * @type {number}
		 * @readonly
		 */
		this.threshold = threshold;

		// Validate parameters
		if (this.polynomial_order < 1 || this.threshold > this.group_size) {
			throw new Error("Threshold is too high or low")
		}

		// Generate initial shares and public key using JVRSS
		[this.shares, this.public_key] = this.jvrss();
	}

	/**
	 * Converts share values to coordinate points for polynomial interpolation
	 * 
	 * Maps each share to a point where x-coordinate is the participant index (1-based)
	 * and y-coordinate is the share value. This format is required for Lagrange
	 * interpolation used in secret reconstruction.
	 * 
	 * @param {BN[]} [shares=[]] - Array of BigNumber share values
	 * @returns {SharePoints} Array of [x, y] points for interpolation
	 * @example
	 * const shares = [new BN("123"), new BN("456"), new BN("789")];
	 * const points = tss.shares_to_points(shares);
	 * // Returns: [[1, 123], [2, 456], [3, 789]]
	 */
	shares_to_points(shares = []) {
		return shares.map((x, i) => [i + 1, x]);
	}

	/**
	 * Joint Verifiable Random Secret Sharing (JVRSS) protocol implementation
	 * 
	 * Generates a shared secret and corresponding public key through a distributed
	 * protocol where each participant contributes randomness:
	 * 1. Each participant generates a random polynomial of degree (threshold-1)
	 * 2. All participants evaluate their polynomials at each participant's index
	 * 3. Shares are summed to create the final secret shares
	 * 4. Public key is computed as the sum of all polynomial constant terms
	 * 
	 * @returns {Array} Array containing secret shares array and aggregate public key
	 * @returns {Array.<BN>} returns.0 - Array of secret shares as BigNumbers
	 * @returns {Point} returns.1 - Aggregate public key point
	 * @example
	 * const [shares, publicKey] = tss.jvrss();
	 * console.log(shares.length);    // Equal to group_size
	 * console.log(publicKey.x);      // Public key x-coordinate
	 */
	jvrss() {
		// Generate random polynomials for each participant
		const polynomials = new Array(this.group_size)
			.fill(null)
			.map(_ => Polynomial.fromRandom(this.polynomial_order));

		// Initialize shares array
		let shares = new Array(this.group_size).fill(new BN(0));

		// Compute shares: sum of all polynomial evaluations at each point
		for (let i = 0; i < this.group_size; i++) {
			for (let j = 0; j < this.group_size; j++) {
				shares[j] = shares[j].add(polynomials[i].evaluate(j + 1));
			}
		}

		// Reduce all shares modulo curve order
		shares = shares.map(val => val.umod(N));

		// Compute aggregate public key from polynomial constant terms
		let public_key = new Point(BigInt(0), BigInt(0));
		for (let i = 0; i < this.group_size; i++) {
			const key = polynomials[i].coefficients[0].toBuffer("be", 32);
			public_key = Point.fromPrivateKey(key).add(public_key);
		}

		return [shares, public_key];
	}

	/**
	 * Additive Secret Sharing (ADDSS) - combines two sets of shares additively
	 * 
	 * Performs element-wise addition of two share arrays and reconstructs the
	 * sum of the original secrets using polynomial interpolation. This operation
	 * is useful for computing linear combinations of secrets.
	 * 
	 * @param {BN[]} [a_shares=[]] - First set of secret shares
	 * @param {BN[]} [b_shares=[]] - Second set of secret shares  
	 * @returns {BN} The sum of the two original secrets
	 * @example
	 * const [shares_a] = tss.jvrss(); // Generate first secret
	 * const [shares_b] = tss.jvrss(); // Generate second secret
	 * const sum_secret = tss.addss(shares_a, shares_b);
	 */
	addss(a_shares = [], b_shares = []) {
		// Element-wise addition of shares
		const shares_addition = new Array(this.group_size)
			.fill(null)
			.map((_, i) => a_shares[i].add(b_shares[i]).umod(N));

		// Select random subset of threshold+1 points for interpolation
		const random_points = this.shares_to_points(shares_addition)
			.sort(() => 0.5 - Math.random()) // Randomize order
			.slice(0, this.polynomial_order + 1); // Take t+1 points

		// Reconstruct secret at x=0 using Lagrange interpolation
		return Polynomial.interpolate_evaluate(random_points, 0);
	}

	/**
	 * Multiplicative Secret Sharing (PROSS) - computes product of shared secrets
	 * 
	 * Performs element-wise multiplication of shares and reconstructs the product
	 * of the original secrets. Requires 2t+1 shares due to the degree doubling
	 * property of polynomial multiplication.
	 * 
	 * @param {BN[]} [a_shares=[]] - First set of secret shares
	 * @param {BN[]} [b_shares=[]] - Second set of secret shares
	 * @returns {BN} The product of the two original secrets
	 * @example
	 * const [shares_a] = tss.jvrss();
	 * const [shares_b] = tss.jvrss();
	 * const product = tss.pross(shares_a, shares_b);
	 */
	pross(a_shares = [], b_shares = []) {
		// Element-wise multiplication of shares
		const shares_product = new Array(this.group_size)
			.fill(null)
			.map((_, i) => a_shares[i].mul(b_shares[i]).umod(N));

		// Need 2t+1 points for degree-2t polynomial reconstruction
		const random_points = this.shares_to_points(shares_product)
			.sort(() => 0.5 - Math.random())
			.slice(0, 2 * this.polynomial_order + 1); // Take 2t+1 points

		return Polynomial.interpolate_evaluate(random_points, 0);
	}

	/**
	 * Inverse Secret Sharing (INVSS) - computes modular inverse of shared secret
	 * 
	 * Computes the modular inverse of a shared secret by:
	 * 1. Generating a random secret b and computing product a*b
	 * 2. Computing modular inverse of (a*b) in the clear
	 * 3. Multiplying b-shares by the inverse to get shares of a^(-1)
	 * 
	 * @param {BN[]} [a_shares=[]] - Shares of the secret to invert
	 * @returns {BN[]} Shares of the modular inverse of the original secret
	 * @example
	 * const [shares] = tss.jvrss();
	 * const inverse_shares = tss.invss(shares);
	 * // inverse_shares contains shares of the modular inverse
	 */
	invss(a_shares = []) {
		// Generate random secret b
		const [b_shares, _] = this.jvrss();

		// Compute product a*b using multiplicative secret sharing
		const pross = this.pross(a_shares, b_shares);

		// Convert to bigint and compute modular inverse
		const x = bufToBigint(pross.toBuffer('be', 32));
		const mod_inv_u = new BN(utils.invert(x, CURVE.n));

		// Multiply b-shares by inverse to get shares of a^(-1)
		const inverse_shares = b_shares.map(val => mod_inv_u.mul(val).umod(N));

		return inverse_shares;
	}

	/**
	 * Reconstructs the private key from secret shares using polynomial interpolation
	 * 
	 * Uses Lagrange interpolation to evaluate the polynomial at x=0, which gives
	 * the original secret (private key). Requires at least 'threshold' number of shares.
	 * 
	 * @param {BN[]} [a_shares] - Secret shares to reconstruct from (defaults to this.shares)
	 * @returns {BN} The reconstructed private key
	 * @example
	 * const privateKey = tss.privite_key();
	 * console.log(privateKey.toString('hex')); // Private key as hex string
	 * 
	 * // Reconstruct from specific shares
	 * const specificShares = [shares[0], shares[1], shares[2]]; // Any threshold number
	 * const reconstructed = tss.privite_key(specificShares);
	 */
	privite_key(a_shares) {
		a_shares = a_shares || this.shares;
		return Polynomial.interpolate_evaluate(this.shares_to_points(a_shares), 0);
	}

	/**
	 * Generates a threshold signature for a given message
	 * 
	 * The threshold signing protocol:
	 * 1. Hash the message using SHA256
	 * 2. Generate random nonce k using JVRSS (ensures unpredictability)
	 * 3. Compute r = k*G (x-coordinate becomes signature r-value)
	 * 4. Compute k^(-1) using inverse secret sharing
	 * 5. Each participant computes s_i = k^(-1) * (hash + r * private_share_i)
	 * 6. Reconstruct final signature s using polynomial interpolation
	 * 7. Return signature (r,s) with recovery information
	 * 
	 * @param {string} message - Message to sign (will be SHA256 hashed)
	 * @returns {ThresholdSignatureResult} Complete signature with metadata
	 * @example
	 * const message = "Hello Threshold Signatures!";
	 * const signature = tss.sign(message);
	 * 
	 * console.log(signature.sig.r);           // r component of signature
	 * console.log(signature.sig.s);           // s component of signature
	 * console.log(signature.serialized_sig);  // Base64 compact format
	 * console.log(signature.recovery_id);     // For public key recovery
	 */
	sign(message) {
		const msgHash = new BN(createHash('sha256').update(Buffer.from(message)).digest());
		let [recovery_id, r, s] = [0, 0, 0];

		// Retry until we get a valid signature
		while (!s) {
			let invss_shares = [];

			// Generate random nonce k and compute r-value
			while (!r) {
				const [k_shares, k_public_key] = this.jvrss();
				const [k_x, k_y] = [new BN(k_public_key.x), new BN(k_public_key.y)];
				r = k_x.umod(N);

				// Compute recovery ID for public key recovery
				recovery_id = 0 | k_x.gt(N) ? 2 : 0 | k_y.modrn(2);

				// Compute inverse of k
				invss_shares = this.invss(k_shares);
			}

			// Compute signature shares: s_i = k^(-1) * (hash + r * share_i)
			let s_shares = [];
			for (let i = 0; i < this.group_size; i++) {
				s_shares.push(
					r.mul(this.shares[i]).add(msgHash).mul(invss_shares[i])
				);
			}

			// Reconstruct final s-value using polynomial interpolation
			s = Polynomial.interpolate_evaluate(this.shares_to_points(s_shares), 0);
		}

		// Convert to standard formats
		[r, s] = [r.toBuffer(), s.toBuffer()];
		const prefix = new BN(27 + recovery_id + 4).toBuffer();
		const serialized_sig = Buffer.concat([prefix, r, s]).toString('base64');

		return {
			sig: secp256k1.Signature.fromCompact(Buffer.concat([r, s])),
			serialized_sig,
			msgHash: msgHash.toBuffer(),
			recovery_id
		};
	}

	/**
	 * Verifies a threshold signature against a public key and message hash
	 * 
	 * Implements ECDSA signature verification using the standard algorithm:
	 * 1. Compute w = s^(-1) mod n
	 * 2. Compute u1 = hash * w mod n
	 * 3. Compute u2 = r * w mod n  
	 * 4. Compute point = u1*G + u2*PublicKey
	 * 5. Verify that point.x ≡ r (mod n)
	 * 
	 * @static
	 * @param {Point} public_key - Elliptic curve public key point
	 * @param {Buffer} msgHash - SHA256 hash of the original message
	 * @param {Signature} sig - Signature object with r and s components
	 * @returns {boolean} True if signature is valid, false otherwise
	 * @example
	 * const signature = tss.sign("Hello World!");
	 * const isValid = ThresholdSignature.verify_threshold_signature(
	 *   tss.public_key, 
	 *   signature.msgHash, 
	 *   signature.sig
	 * );
	 * console.log(isValid); // true
	 */
	static verify_threshold_signature(public_key, msgHash, sig) {
		msgHash = new BN(msgHash);

		// Compute modular inverse of s
		const w = new BN(utils.invert(sig.s, CURVE.n));

		// Compute verification scalars
		const u1 = w.mul(msgHash).umod(N).toBuffer('be', 32);
		const u2 = w.mul(new BN(sig.r)).umod(N).toBuffer('be', 32);

		// Compute verification point: u1*G + u2*PublicKey
		const x = Point.fromPrivateKey(u1).add(public_key.multiply(bufToBigint(u2))).x

		// Verify that x-coordinate matches r-component
		return sig.r === x % CURVE.n;
	}
}

export default ThresholdSignature;