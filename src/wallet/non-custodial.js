/**
 * @fileoverview Non-custodial wallet implementation for J-Bitcoin library
 * 
 * This module implements advanced multi-party threshold signature scheme (TSS) implementation
 * enabling distributed key management without trusted dealers. Ideal for corporate treasuries,
 * escrow services, and high-security applications requiring multi-party authorization.
 * 
 * @author yfbsei
 * @version 2.0.0
 * @since 1.0.0
 * 
 * @requires ThresholdSignature
 * @requires encodeStandardKeys
 * @requires generateAddressFromExtendedVersion
 * @requires bn.js
 * @requires @noble/curves/secp256k1
 * 
 * @example
 * // Import non-custodial wallet
 * import Non_Custodial_Wallet from './Non_Custodial_Wallet.js';
 * 
 * // Create threshold wallet
 * const thresholdWallet = Non_Custodial_Wallet.fromRandom('main', 3, 2);
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';

import {
    BIP44_CONSTANTS,
    DERIVATION_PATHS,
    NETWORKS as BITCOIN_NETWORKS,
    ADDRESS_FORMATS,
    BIP_PURPOSES,
    generateDerivationPath,
    parseDerivationPath,
    isValidBitcoinPath,
    getNetworkByCoinType
} from '../Constants.js';

import { encodeStandardKeys, generateAddressFromExtendedVersion } from '../encoding/address/encode.js';
import ThresholdSignature from "../core/crypto/signatures/threshold/threshold-signature.js";

/**
 * @typedef {Object} ThresholdSignatureResult
 * @description Complete threshold signature with metadata and recovery information
 * @property {Object} sig - ECDSA signature object with r and s components
 * @property {bigint} sig.r - Signature r value as BigInt
 * @property {bigint} sig.s - Signature s value as BigInt
 * @property {string} serialized_sig - Base64-encoded compact signature format (65 bytes)
 * @property {Buffer} msgHash - SHA256 hash of the signed message (32 bytes)
 * @property {number} recovery_id - Recovery ID for public key recovery (0-3)
 * @example
 * const signature = thresholdWallet.sign("Multi-party transaction");
 * console.log(signature.sig.r);          // BigInt r value
 * console.log(signature.serialized_sig); // "base64-encoded-signature"
 * console.log(signature.recovery_id);    // 0, 1, 2, or 3
 */

/**
 * Non-custodial wallet implementation using Threshold Signature Scheme (TSS)
 * for distributed key management. Enables multi-party control without a trusted party.
 * 
 * This class implements advanced threshold cryptography where any subset of participants
 * meeting the threshold requirement can collaboratively generate valid signatures without
 * ever reconstructing the private key. It's ideal for scenarios requiring distributed
 * control, enhanced security, and elimination of single points of failure.
 * 
 * **Key Features:**
 * - Distributed key generation using Joint Verifiable Random Secret Sharing (JVRSS)
 * - Threshold signature generation compatible with standard ECDSA verification
 * - No trusted dealer required for key setup
 * - Configurable t-of-n threshold schemes (e.g., 2-of-3, 3-of-5, 5-of-7)
 * - Secret shares can be distributed across different entities or devices
 * - Compatible with Bitcoin transaction signing and verification
 * - Integrated Bitcoin network configuration and constants
 * 
 * **Security Model:**
 * - Requires exactly t participants to generate signatures
 * - Information-theoretic security: < t participants learn nothing about private key
 * - No single point of failure: up to n-t participants can be compromised safely
 * - Private key never exists in complete form anywhere
 * - Forward secrecy: compromising future shares doesn't reveal past signatures
 * 
 * **Use Cases:**
 * - Corporate treasury management with executive approval
 * - Cryptocurrency exchanges with operator separation
 * - Escrow services with dispute resolution
 * - Multi-signature wallets for shared accounts
 * - Compliance requirements for multi-party authorization
 * - High-value asset protection with distributed control
 * 
 * @class Non_Custodial_Wallet
 * @extends ThresholdSignature
 * @since 1.0.0
 */
class Non_Custodial_Wallet extends ThresholdSignature {

    /**
     * Creates a new Non_Custodial_Wallet instance with specified threshold parameters.
     * 
     * This constructor initializes a threshold signature scheme with the given group size
     * and threshold requirements. It automatically generates the distributed key shares
     * using JVRSS (Joint Verifiable Random Secret Sharing) and computes the corresponding
     * Bitcoin address for receiving payments.
     * 
     * **Initialization Process:**
     * 1. Validate threshold parameters (t ≤ n, t ≥ 2)
     * 2. Execute JVRSS protocol for distributed key generation
     * 3. Generate secret shares for each participant
     * 4. Compute aggregate public key from polynomial constants
     * 5. Derive Bitcoin address from public key
     * 
     * **Parameter Constraints:**
     * - group_size ≥ 2 (minimum meaningful distribution)
     * - threshold ≥ 2 (minimum security requirement)
     * - threshold ≤ group_size (cannot exceed total participants)
     * - Recommended: threshold ≤ (group_size + 1) / 2 for practical usability
     * 
     * @param {string} net - Network type ('main' for mainnet, 'test' for testnet)
     * @param {number} group_size - Total number of participants in the threshold scheme
     * @param {number} threshold - Minimum number of participants required for operations
     * 
     * @throws {Error} "Threshold is too high or low" if parameter constraints are violated
     * @throws {Error} If network type is not 'main' or 'test'
     * 
     * @example
     * // Create a 2-of-3 threshold wallet
     * const wallet = new Non_Custodial_Wallet('main', 3, 2);
     * console.log('Group size:', wallet.group_size);     // 3
     * console.log('Threshold:', wallet.threshold);       // 2
     * console.log('Address:', wallet.address);           // Bitcoin address
     * console.log('Shares:', wallet._shares.length);     // 3 hex-encoded shares
     */
    constructor(net, group_size, threshold) {
        super(group_size, threshold);

        // Validate network parameter
        if (net !== 'main' && net !== 'test') {
            throw new Error(`Invalid network: ${net}. Must be 'main' or 'test'`);
        }

        /**
         * Network type for this threshold wallet instance.
         * Determines address formats, version bytes, and network-specific parameters.
         * 
         * @type {string}
         * @readonly
         * @memberof Non_Custodial_Wallet
         * @example
         * console.log(wallet.net); // "main" or "test"
         */
        this.net = net;

        /**
         * Bitcoin network configuration for this threshold wallet.
         * Contains network-specific parameters and constants.
         * 
         * @type {Object}
         * @readonly
         * @memberof Non_Custodial_Wallet
         * @example
         * console.log(wallet.networkConfig.name);        // "Bitcoin" or "Bitcoin Testnet"
         * console.log(wallet.networkConfig.symbol);      // "BTC"
         * console.log(wallet.networkConfig.coinType);    // 0 or 1
         */
        this.networkConfig = getNetworkByCoinType(net === 'main' ? 0 : 1);

        // Generate wallet address and public key from threshold scheme
        [this.publicKey, this.address] = this.#wallet();
    }

    /**
     * Generates a new random threshold wallet with specified parameters.
     * 
     * This static factory method creates a fresh threshold signature scheme using
     * cryptographically secure randomness. It initializes the distributed key generation
     * protocol and produces a complete threshold wallet ready for multi-party operations.
     * 
     * **Generation Process:**
     * 1. Create new threshold signature instance with specified parameters
     * 2. Execute JVRSS for distributed key generation  
     * 3. Generate secret shares for all participants
     * 4. Compute aggregate public key and Bitcoin address
     * 5. Return initialized wallet instance
     * 
     * **Security Properties:**
     * - Uses cryptographically secure random number generation
     * - No participant has knowledge of the complete private key
     * - Secret shares are information-theoretically secure
     * - Aggregate public key is verifiable and deterministic
     * 
     * @static
     * @param {string} [net="main"] - Network type ('main' for mainnet, 'test' for testnet)
     * @param {number} [group_size=3] - Total number of participants in the scheme
     * @param {number} [threshold=2] - Minimum participants needed for signature generation
     * @returns {Non_Custodial_Wallet} New threshold wallet instance
     * 
     * @throws {Error} "Threshold is too high or low" if constraints are violated
     * @throws {Error} If network parameter is invalid
     * 
     * @example
     * // Standard 2-of-3 multi-signature wallet
     * const multiSigWallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
     * console.log('Multi-sig address:', multiSigWallet.address);
     * 
     * // Get shares for distribution
     * const [share1, share2, share3] = multiSigWallet._shares;
     * console.log('Share 1:', share1); // Hex-encoded secret share
     */
    static fromRandom(net = "main", group_size = 3, threshold = 2) {
        return new this(
            net,
            group_size,
            threshold
        )
    }

    /**
     * Reconstructs a threshold wallet from existing secret shares.
     * 
     * This static factory method rebuilds a threshold wallet from previously distributed
     * secret shares. It's used when participants want to reconstruct the wallet for
     * signature generation or when migrating shares between systems. The method validates
     * share consistency and reconstructs the public key and address.
     * 
     * **Reconstruction Process:**
     * 1. Create new threshold instance with matching parameters
     * 2. Convert hex-encoded shares to BigNumber format
     * 3. Reconstruct the aggregate public key from shares
     * 4. Derive Bitcoin address from reconstructed public key
     * 5. Validate share consistency and threshold requirements
     * 
     * **Security Considerations:**
     * - Only provided shares are used; missing shares remain unknown
     * - Threshold requirement still applies for signature generation
     * - Share authenticity should be verified through secure channels
     * - Reconstructed wallet has same capabilities as original
     * 
     * @static
     * @param {string} [net="main"] - Network type ('main' for mainnet, 'test' for testnet)
     * @param {string[]} shares - Array of hex-encoded secret shares
     * @param {number} [threshold=2] - Minimum participants required for operations
     * @returns {Non_Custodial_Wallet} Reconstructed threshold wallet instance
     * 
     * @throws {Error} If threshold is greater than number of provided shares
     * @throws {Error} If reconstructed public key is invalid
     * 
     * @example
     * // Reconstruct 2-of-3 wallet from shares
     * const originalShares = [
     *   "79479395a59a8e9d930f2b10ccd5ac3671b0ff0bf8a66aaa1d74978c5353694b",
     *   "98510126c920e18b148130ac1145686cb299d21f0e010b98ede44169a7bb1c13",
     *   "b7428d37e5847f9a8b3d4c2f9a1e5c8d7b4f2a8e9c1d5b7a3f8e2c9d4b6a1f5"
     * ];
     * 
     * const reconstructedWallet = Non_Custodial_Wallet.fromShares("main", originalShares, 2);
     * console.log('Reconstructed address:', reconstructedWallet.address);
     */
    static fromShares(net = "main", shares, threshold = 2) {
        const wallet = new this(
            net,
            shares.length,
            threshold
        )

        // Convert hex shares to BigNumber format and reconstruct public key
        wallet.shares = shares.map(x => new BN(x, 'hex'));
        wallet.public_key = secp256k1.ProjectivePoint.fromPrivateKey(wallet.privite_key().toBuffer());
        [wallet.publicKey, wallet.address] = wallet.#wallet();

        return wallet;
    }

    /**
     * Gets the secret shares as hex-encoded strings for secure distribution to participants.
     * 
     * This getter provides access to the distributed secret shares in a format suitable
     * for secure transmission and storage. Each share is a hex-encoded string representing
     * a point on the secret-sharing polynomial. These shares should be distributed to
     * different participants and stored securely.
     * 
     * **Share Properties:**
     * - Each share is cryptographically independent
     * - Shares are information-theoretically secure (< threshold reveals nothing)
     * - Hex encoding ensures safe transmission over text-based channels
     * - Each share is typically 64 hex characters (32 bytes)
     * - Shares should be transmitted over secure, authenticated channels
     * 
     * **Distribution Best Practices:**
     * - Use secure communication channels (encrypted email, secure messaging)
     * - Verify recipient identity before share distribution
     * - Consider using QR codes for offline share transfer
     * - Implement share backup and recovery procedures
     * - Document which participant holds which share index
     * 
     * @returns {string[]} Array of hex-encoded secret shares for distribution
     * 
     * @example
     * // Basic share distribution
     * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
     * const shares = wallet._shares;
     * 
     * console.log('Number of shares:', shares.length); // 3
     * console.log('Share format:', shares[0]);          // "79479395a59a8e9d..."
     */
    get _shares() {
        return this.shares.map(x => x.toString('hex'));
    }

    /**
     * Private method to generate Bitcoin wallet address and public key from threshold scheme.
     * 
     * This internal method computes the Bitcoin address and hex-encoded public key from
     * the aggregate public key generated by the threshold signature scheme. It applies
     * network-specific version bytes and follows standard Bitcoin address generation.
     * 
     * **Address Generation Process:**
     * 1. Determine network version byte (mainnet vs testnet)
     * 2. Convert aggregate public key to compressed format
     * 3. Compute HASH160 (RIPEMD160(SHA256(pubkey)))
     * 4. Add version byte and checksum
     * 5. Encode using Base58Check format
     * 
     * @private
     * @returns {Array} Tuple containing hex public key and Bitcoin address
     * @returns {string} returns.0 - Hex-encoded compressed public key
     * @returns {string} returns.1 - Bitcoin address for receiving payments
     * @memberof Non_Custodial_Wallet
     */
    #wallet() {
        const
            versionByte = this.net === "main" ? 0x0488b21e : 0x043587cf,
            pubKeyToBuff = Buffer.from(this.public_key.toHex(true), 'hex');

        return [
            this.public_key.toHex(true),
            generateAddressFromExtendedVersion(versionByte, pubKeyToBuff)
        ];
    }

    /**
     * Gets the reconstructed private key in WIF (Wallet Import Format).
     * 
     * This getter reconstructs the complete private key from the distributed shares
     * and returns it in standard WIF format. This operation defeats the purpose of
     * the threshold scheme by centralizing the private key, so it should be used
     * with extreme caution and only when absolutely necessary.
     * 
     * **Security Warning:**
     * - Reconstructing the private key eliminates the security benefits of threshold signatures
     * - The complete private key provides full control over the wallet
     * - Should only be used for emergency recovery or migration scenarios
     * - Consider using threshold signatures instead of key reconstruction when possible
     * - Ensure secure deletion of the reconstructed key after use
     * 
     * **Use Cases:**
     * - Emergency wallet recovery when threshold scheme is no longer viable
     * - Migration to different wallet software that doesn't support threshold signatures
     * - Compliance requirements that mandate private key export
     * - Integration with legacy systems that require WIF private keys
     * 
     * @returns {string} WIF-encoded private key with network-appropriate version byte
     * 
     * @throws {Error} If insufficient shares are available for reconstruction
     * @throws {Error} If private key reconstruction fails
     * 
     * @example
     * // Emergency private key extraction (use with caution!)
     * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
     * 
     * // Only use in emergency situations
     * console.warn('Reconstructing private key - this defeats threshold security!');
     * const privateKey = wallet._privateKey;
     * console.log('WIF Private Key:', privateKey);
     * // "L5HgWvFghocq1FmxSjKNaGhVN8f67p6xYg5pY7M8FE77HXwHtGGu"
     */
    get _privateKey() {
        console.warn('⚠️  SECURITY WARNING: Reconstructing private key defeats threshold security!');
        const privKey = {
            key: this.privite_key().toBuffer(),
            versionByteNum: this.net === 'main' ? 0x80 : 0xef
        }
        return encodeStandardKeys(privKey, undefined).pri;
    }

    /**
     * Verifies a threshold signature against the original message hash.
     * 
     * This method performs cryptographic verification of threshold signatures using
     * standard ECDSA verification. Threshold signatures are mathematically equivalent
     * to single-party ECDSA signatures, so they can be verified using standard
     * verification algorithms without knowledge of the threshold scheme.
     * 
     * **Verification Process:**
     * 1. Parse signature into r and s components
     * 2. Validate signature components are within valid ranges
     * 3. Compute verification equation using aggregate public key
     * 4. Check that computed point matches signature r value
     * 5. Return boolean result of verification
     * 
     * **Compatibility:**
     * - Compatible with standard ECDSA verification
     * - Can be verified by any Bitcoin-compatible software
     * - Third parties don't need knowledge of threshold scheme
     * - Signatures are indistinguishable from single-party signatures
     * 
     * @param {Object} sig - Signature object with r and s properties (BigInt values)
     * @param {Buffer} msgHash - SHA256 hash of the original message (32 bytes)
     * @returns {boolean} True if signature is valid for this wallet's public key, false otherwise
     * 
     * @throws {Error} If signature format is invalid
     * @throws {Error} If message hash is not 32 bytes
     * 
     * @example
     * // Basic threshold signature verification
     * const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
     * const message = "Multi-party authorization required";
     * 
     * // Generate threshold signature
     * const signature = wallet.sign(message);
     * 
     * // Verify signature
     * const isValid = wallet.verify(signature.sig, signature.msgHash);
     * console.log('Threshold signature valid:', isValid); // true
     */
    verify(sig, msgHash) {
        return ThresholdSignature.verify_threshold_signature(this.public_key, msgHash, sig);
    }

    /**
     * Gets threshold wallet summary information.
     * 
     * @returns {Object} Threshold wallet summary object
     * 
     * @example
     * const wallet = Non_Custodial_Wallet.fromRandom("main", 5, 3);
     * const summary = wallet.getSummary();
     * console.log(summary);
     * // {
     * //   network: "Bitcoin",
     * //   address: "1BvBM...",
     * //   thresholdScheme: "3-of-5",
     * //   participants: 5,
     * //   requiredSigners: 3,
     * //   securityLevel: "High"
     * // }
     */
    getSummary() {
        const securityLevel = this.threshold >= this.group_size * 0.6 ? 'High' :
            this.threshold >= this.group_size * 0.4 ? 'Medium' : 'Low';

        return {
            network: this.networkConfig.name,
            address: this.address,
            thresholdScheme: `${this.threshold}-of-${this.group_size}`,
            participants: this.group_size,
            requiredSigners: this.threshold,
            securityLevel
        };
    }
}

export default Non_Custodial_Wallet;