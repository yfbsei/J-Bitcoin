/**
 * @fileoverview Schnorr signature implementation for Bitcoin (BIP340)
 * 
 * This module implements Schnorr signatures according to BIP340 specification,
 * providing a more efficient and privacy-friendly alternative to ECDSA.
 * Schnorr signatures enable key aggregation, signature aggregation, and
 * improved multi-signature schemes.
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki|BIP340 - Schnorr Signatures for secp256k1}
 * @see {@link https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_schnorrsig.h|libsecp256k1 Schnorr API}
 * @author yfbsei
 * @version 1.0.0
 */

import { randomBytes } from 'node:crypto';

import { schnorr } from '@noble/curves/secp256k1';

import { decodeWIFPrivateKey } from '../../../encoding/address/decode.js';

/**
 * Schnorr signature operations for Bitcoin according to BIP340
 * 
 * Provides comprehensive Schnorr signature functionality including:
 * - Deterministic and randomized signature generation
 * - Public key derivation from private keys
 * - Signature verification with proper point validation
 * - Integration with Bitcoin's Taproot upgrade
 * 
 * Key advantages over ECDSA:
 * - Linear signature aggregation
 * - Smaller signature size (64 bytes vs 71-73 bytes for ECDSA)
 * - Batch verification for improved performance
 * - Eliminates signature malleability
 * - Enables more sophisticated multi-signature schemes
 * 
 * @namespace schnorr_sig
 * @example
 * // Basic Schnorr signature workflow
 * const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
 * const message = "Hello Schnorr!";
 * 
 * // Sign the message
 * const signature = schnorr_sig.sign(privateKey, message);
 * 
 * // Get the public key
 * const publicKey = schnorr_sig.retrieve_public_key(privateKey);
 * 
 * // Verify the signature
 * const isValid = schnorr_sig.verify(signature, message, publicKey);
 * console.log(isValid); // true
 */
const schnorr_sig = {
    /**
     * Creates a Schnorr signature for a given message using BIP340 specification
     * 
     * The signing process follows BIP340:
     * 1. Parse and validate the private key
     * 2. Compute the public key P = d*G (where d is private key)
     * 3. Generate nonce k using auxiliary randomness (prevents side-channel attacks)
     * 4. Compute R = k*G and ensure R.y is even (BIP340 requirement)
     * 5. Compute challenge e = SHA256(R.x || P || m)
     * 6. Compute signature s = (k + e*d) mod n
     * 7. Return signature as 64-byte array: R.x || s
     * 
     * @param {string} [private_key="L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS"] - WIF-encoded private key
     * @param {string} [msg="Hello world"] - Message to sign (will be UTF-8 encoded)
     * @param {Uint8Array} [auxRand=randomBytes(32)] - 32 bytes of auxiliary randomness for nonce generation
     * @returns {Uint8Array} 64-byte Schnorr signature (32-byte R.x + 32-byte s)
     * @throws {Error} If private key is invalid or signing fails
     * @example
     * // Sign with default randomness
     * const signature = schnorr_sig.sign(privateKey, "Hello Bitcoin!");
     * console.log(signature.length); // 64 bytes
     * 
     * // Sign with custom auxiliary randomness
     * const customAux = new Uint8Array(32).fill(0xaa);
     * const deterministicSig = schnorr_sig.sign(privateKey, "Hello Bitcoin!", customAux);
     * 
     * // Multiple signatures of same message with different aux data will differ
     * const sig1 = schnorr_sig.sign(privateKey, "test", new Uint8Array(32).fill(1));
     * const sig2 = schnorr_sig.sign(privateKey, "test", new Uint8Array(32).fill(2));
     * console.log(Buffer.from(sig1).equals(Buffer.from(sig2))); // false
     */
    sign(private_key = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", msg = "Hello world", auxRand = randomBytes(32)) {
        msg = Buffer.from(msg);
        private_key = decodeWIFPrivateKey(private_key);
        return schnorr.sign(msg, private_key, auxRand)
    },

    /**
     * Verifies a Schnorr signature against a message and public key
     * 
     * The verification process implements BIP340 algorithm:
     * 1. Parse the 64-byte signature into R.x (32 bytes) and s (32 bytes)
     * 2. Validate that R.x and s are valid field elements
     * 3. Compute challenge e = SHA256(R.x || P || m)
     * 4. Compute point S = s*G - e*P
     * 5. Verify that S.x == R.x and S.y is even
     * 
     * This verification is more efficient than ECDSA and allows for batch
     * verification when verifying multiple signatures simultaneously.
     * 
     * @param {Uint8Array|Buffer} sig - 64-byte Schnorr signature to verify
     * @param {string} [msg="Hello World"] - Original message that was signed
     * @param {Uint8Array|Buffer} public_key - 32-byte x-only public key (BIP340 format)
     * @returns {boolean} True if signature is valid, false otherwise
     * @example
     * // Standard verification
     * const signature = schnorr_sig.sign(privateKey, "Hello Schnorr!");
     * const publicKey = schnorr_sig.retrieve_public_key(privateKey);
     * const isValid = schnorr_sig.verify(signature, "Hello Schnorr!", publicKey);
     * console.log(isValid); // true
     * 
     * // Invalid signature detection
     * const invalidSig = new Uint8Array(64); // All zeros
     * const isInvalid = schnorr_sig.verify(invalidSig, "test", publicKey);
     * console.log(isInvalid); // false
     * 
     * // Wrong message detection
     * const wrongMsg = schnorr_sig.verify(signature, "Wrong message", publicKey);
     * console.log(wrongMsg); // false
     */
    verify(sig, msg = "Hello World", public_key) {
        msg = Buffer.from(msg);
        return schnorr.verify(sig, msg, public_key)
    },

    /**
     * Derives the Schnorr public key from a private key according to BIP340
     * 
     * Computes the x-only public key representation used in BIP340:
     * 1. Compute the full public key point P = d*G
     * 2. If P.y is odd, negate d to make P.y even
     * 3. Return only the x-coordinate (32 bytes)
     * 
     * The x-only representation saves space and simplifies signature verification
     * while maintaining the same security properties as full public keys.
     * 
     * @param {string} [private_key="L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS"] - WIF-encoded private key
     * @returns {Uint8Array} 32-byte x-only public key for use with Schnorr signatures
     * @throws {Error} If private key is invalid
     * @example
     * // Get public key for Schnorr operations
     * const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
     * const publicKey = schnorr_sig.retrieve_public_key(privateKey);
     * console.log(publicKey.length); // 32 bytes (x-only)
     * 
     * // Use in signature verification
     * const message = "Taproot transaction";
     * const signature = schnorr_sig.sign(privateKey, message);
     * const verified = schnorr_sig.verify(signature, message, publicKey);
     * console.log(verified); // true
     * 
     * // Compare with different private key
     * const otherPrivKey = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
     * const otherPubKey = schnorr_sig.retrieve_public_key(otherPrivKey);
     * console.log(Buffer.from(publicKey).equals(Buffer.from(otherPubKey))); // false
     */
    retrieve_public_key(private_key = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS") {
        private_key = decodeWIFPrivateKey(private_key);
        return schnorr.getPublicKey(private_key)
    }
}

export default schnorr_sig;