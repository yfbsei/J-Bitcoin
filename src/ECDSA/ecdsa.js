/**
 * @fileoverview ECDSA (Elliptic Curve Digital Signature Algorithm) implementation
 * 
 * This module provides ECDSA signature generation and verification using the secp256k1
 * elliptic curve, which is the standard curve used in Bitcoin. It includes functionality
 * for signing messages, verifying signatures, and recovering public keys from signatures.
 * 
 * @see {@link https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm|ECDSA on Bitcoin Wiki}
 * @author yfbsei
 * @version 1.0.0
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { privateKey_decode } from '../utilities/decodeKeys.js';

/**
 * @typedef {Array} ECDSASignatureResult
 * @description Array containing signature bytes and recovery ID
 * @property {Uint8Array} 0 - DER-encoded signature bytes
 * @property {number} 1 - Recovery ID (0-3) for public key recovery
 */

/**
 * ECDSA cryptographic operations for Bitcoin
 * 
 * Provides comprehensive ECDSA functionality including deterministic signature generation
 * (RFC 6979), signature verification, and public key recovery. All operations use the
 * secp256k1 elliptic curve as required by Bitcoin.
 * 
 * @namespace ECDSA
 * @example
 * // Sign a message
 * const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
 * const [signature, recoveryId] = ECDSA.sign(privateKey, "Hello Bitcoin!");
 * 
 * // Recover public key from signature
 * const publicKey = ECDSA.retrieve_public_key("Hello Bitcoin!", signature, recoveryId);
 * 
 * // Verify signature
 * const isValid = ECDSA.verify(signature, "Hello Bitcoin!", publicKey);
 */
const ECDSA = {

    /**
     * Signs a message using ECDSA with deterministic k-value generation (RFC 6979)
     * 
     * The signing process:
     * 1. Decodes the WIF-encoded private key
     * 2. Converts the message to a buffer
     * 3. Generates a deterministic signature using RFC 6979
     * 4. Returns both the signature and recovery ID for public key recovery
     * 
     * @param {string} [private_key="L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS"] - WIF-encoded private key
     * @param {string} [msg="Hello world"] - Message to sign (will be UTF-8 encoded)
     * @returns {ECDSASignatureResult} Array containing signature and recovery ID
     * @throws {Error} If private key is invalid or signing fails
     * @example
     * const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
     * const message = "Hello Bitcoin!";
     * const [signature, recoveryId] = ECDSA.sign(privateKey, message);
     * 
     * console.log(signature);   // Uint8Array with DER-encoded signature
     * console.log(recoveryId);  // Number 0-3 for public key recovery
     */
    sign(private_key = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", msg = "Hello world") {
        msg = Buffer.from(msg);
        private_key = privateKey_decode(private_key);
        const signature = secp256k1.sign(msg, private_key);
        return [signature.toCompactRawBytes(), signature.recovery || 0];
    },

    /**
     * Verifies an ECDSA signature against a message using a public key
     * 
     * Performs cryptographic verification to ensure that the signature was created
     * by the holder of the private key corresponding to the given public key.
     * 
     * @param {Uint8Array|Buffer} sig - DER-encoded signature bytes
     * @param {string} [msg="Hello World"] - Original message that was signed
     * @param {Uint8Array|Buffer} public_key - Compressed or uncompressed public key
     * @returns {boolean} True if signature is valid, false otherwise
     * @example
     * const [signature, _] = ECDSA.sign(privateKey, "Hello Bitcoin!");
     * const publicKey = ECDSA.retrieve_public_key("Hello Bitcoin!", signature, recoveryId);
     * const isValid = ECDSA.verify(signature, "Hello Bitcoin!", publicKey);
     * console.log(isValid); // true
     * 
     * // Invalid signature
     * const isInvalid = ECDSA.verify(signature, "Different message", publicKey);
     * console.log(isInvalid); // false
     */
    verify(sig, msg = "Hello World", public_key) {
        msg = Buffer.from(msg);
        return secp256k1.verify(sig, msg, public_key);
    },

    /**
     * Recovers the public key from a signature and message using the recovery ID
     * 
     * This function enables public key recovery without prior knowledge of the public key,
     * which is useful for applications like Ethereum-style address recovery and
     * signature verification workflows.
     * 
     * @param {string} [msg="Hello world"] - Original message that was signed
     * @param {Uint8Array|Buffer} sig - DER-encoded signature bytes
     * @param {number} [recovery=0] - Recovery ID (0-3) obtained during signing
     * @returns {Uint8Array} Compressed public key (33 bytes)
     * @throws {Error} If recovery fails or parameters are invalid
     * @example
     * const message = "Hello Bitcoin!";
     * const [signature, recoveryId] = ECDSA.sign(privateKey, message);
     * const recoveredPubKey = ECDSA.retrieve_public_key(message, signature, recoveryId);
     * 
     * // The recovered public key should match the original
     * const originalPubKey = getPublicKey(privateKey_decode(privateKey), true);
     * console.log(Buffer.from(recoveredPubKey).equals(Buffer.from(originalPubKey))); // true
     */
    retrieve_public_key(msg = "Hello world", sig, recovery = 0) {
        msg = Buffer.from(msg);
        const signature = secp256k1.Signature.fromCompact(sig).addRecoveryBit(recovery);
        const point = signature.recoverPublicKey(msg);
        return point.toRawBytes(true);
    }
}

// Example usage demonstrating the complete ECDSA workflow
// const 
//     [private_key, message] = ["L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", "Jamallo"],
//     [sig, recovery] = ECDSA.sign(private_key, message),
//     public_key = ECDSA.retrieve_public_key(message, sig, recovery);

// ECDSA.verify(sig, message, public_key) // true

export default ECDSA;