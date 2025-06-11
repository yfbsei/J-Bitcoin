/**
 * @fileoverview TypeScript definitions for J-Bitcoin Library
 * @version 2.0.0
 * @description Type definitions for enterprise-grade Bitcoin library with HD wallets,
 *              threshold signatures, and full BIP compliance.
 * @author yfbsei
 * @license ISC
 */

declare module 'j-bitcoin' {
    // =============================================================================
    // CORE TYPES AND INTERFACES
    // =============================================================================

    /** Bitcoin network types */
    type BitcoinNetwork = 'main' | 'test';

    /** Address types supported by the library */
    type AddressType = 'legacy' | 'segwit' | 'taproot';

    /** Key derivation purposes (BIP44) */
    type BIPPurpose = 44 | 49 | 84 | 86;

    /** Key type for hierarchical deterministic keys */
    type KeyType = 'pri' | 'pub';

    /** Buffer-like types accepted by the library */
    type BufferLike = Buffer | Uint8Array | ArrayBuffer;

    // =============================================================================
    // NETWORK CONFIGURATION
    // =============================================================================

    /** Network configuration interface */
    interface NetworkConfig {
        /** Human-readable network name */
        name: string;
        /** Currency symbol */
        symbol: string;
        /** Network identifier */
        network: BitcoinNetwork;
        /** Chain ID for identification */
        chainId: number;
        /** BIP44 coin type */
        bip44CoinType: 0 | 1;
    }

    // =============================================================================
    // KEY AND ADDRESS INTERFACES
    // =============================================================================

    /** Hierarchical deterministic key pair */
    interface HDKeys {
        /** Extended private key in xprv/tprv format */
        HDpri: string;
        /** Extended public key in xpub/tpub format */
        HDpub: string;
    }

    /** Standard key pair for Bitcoin operations */
    interface KeyPair {
        /** WIF-encoded private key */
        pri: string;
        /** Hex-encoded compressed public key */
        pub: string;
    }

    /** Derived child key information */
    interface DerivedKey {
        /** Bitcoin address */
        address: string;
        /** Private key in WIF format */
        privateKey: string;
        /** Public key in hex format */
        publicKey: string;
        /** Derivation path used */
        derivationPath: string;
        /** Address type */
        addressType: AddressType;
    }

    /** Derivation path options */
    interface DerivationPathOptions {
        /** BIP purpose (default: 44) */
        purpose?: BIPPurpose;
        /** Coin type (0=mainnet, 1=testnet) */
        coinType?: 0 | 1;
        /** Account index (default: 0) */
        account?: number;
        /** Change type (0=external, 1=internal/change) */
        change?: 0 | 1;
        /** Address index (default: 0) */
        addressIndex?: number;
    }

    /** Parsed derivation path components */
    interface ParsedDerivationPath {
        purpose: number;
        coinType: number;
        account: number;
        change: number;
        addressIndex: number;
    }

    // =============================================================================
    // SIGNATURE AND CRYPTOGRAPHY INTERFACES
    // =============================================================================

    /** ECDSA signature result */
    interface ECDSASignature {
        /** Signature r component */
        r: bigint;
        /** Signature s component */
        s: bigint;
        /** Recovery ID */
        recovery?: number;
    }

    /** Schnorr signature result */
    interface SchnorrSignature {
        /** Signature bytes (64 bytes) */
        signature: Uint8Array;
        /** Message hash that was signed */
        messageHash: Uint8Array;
    }

    /** Threshold signature result */
    interface ThresholdSignatureResult {
        /** Signature r component */
        r: bigint;
        /** Signature s component */
        s: bigint;
        /** Number of participants */
        participants: number;
        /** Threshold required */
        threshold: number;
        /** Signature metadata */
        metadata: {
            /** Timestamp of signature creation */
            timestamp: number;
            /** Signing algorithm used */
            algorithm: 'ecdsa' | 'schnorr';
        };
    }

    /** Polynomial share for threshold signatures */
    interface PolynomialShare {
        /** X-coordinate */
        x: bigint;
        /** Y-coordinate (secret share) */
        y: bigint;
        /** Share index */
        index: number;
    }

    // =============================================================================
    // TRANSACTION INTERFACES
    // =============================================================================

    /** UTXO (Unspent Transaction Output) */
    interface UTXO {
        /** Transaction ID */
        txid: string;
        /** Output index */
        vout: number;
        /** Value in satoshis */
        value: number;
        /** Locking script */
        scriptPubKey: string;
        /** Address associated with UTXO */
        address?: string;
    }

    /** Transaction input */
    interface TransactionInput {
        /** Previous transaction hash */
        txid: string;
        /** Previous output index */
        vout: number;
        /** Unlocking script */
        scriptSig: string;
        /** Sequence number */
        sequence?: number;
    }

    /** Transaction output */
    interface TransactionOutput {
        /** Value in satoshis */
        value: number;
        /** Locking script */
        scriptPubKey: string;
        /** Recipient address */
        address?: string;
    }

    /** Bitcoin transaction */
    interface Transaction {
        /** Transaction version */
        version: number;
        /** Transaction inputs */
        inputs: TransactionInput[];
        /** Transaction outputs */
        outputs: TransactionOutput[];
        /** Lock time */
        locktime: number;
        /** Transaction ID (calculated) */
        txid?: string;
    }

    // =============================================================================
    // TAPROOT INTERFACES
    // =============================================================================

    /** Taproot control block */
    interface ControlBlock {
        /** Leaf version and parity */
        version: number;
        /** Internal public key */
        internalKey: Uint8Array;
        /** Merkle path */
        merklePath: Uint8Array[];
    }

    /** Taproot merkle tree node */
    interface MerkleNode {
        /** Node hash */
        hash: Uint8Array;
        /** Left child (if internal node) */
        left?: MerkleNode;
        /** Right child (if internal node) */
        right?: MerkleNode;
        /** Script data (if leaf node) */
        script?: Uint8Array;
    }

    // =============================================================================
    // WALLET CLASSES
    // =============================================================================

    /**
     * Custodial wallet implementation for managed Bitcoin operations
     */
    export class CustodialWallet {
        /**
         * Create a new custodial wallet
         * @param network Bitcoin network to use
         * @param seed Optional seed for deterministic generation
         */
        constructor(network: BitcoinNetwork, seed?: BufferLike);

        /**
         * Generate a new address
         * @param addressType Type of address to generate
         * @returns Generated address information
         */
        generateAddress(addressType: AddressType): DerivedKey;

        /**
         * Sign a message with the wallet's private key
         * @param message Message to sign
         * @returns Signature result
         */
        signMessage(message: string): ECDSASignature;

        /**
         * Get wallet's master public key
         * @returns Extended public key
         */
        getMasterPublicKey(): string;

        /**
         * Derive a child key at the specified path
         * @param account Account index
         * @param change Change type (0=external, 1=internal)
         * @param addressIndex Address index
         * @param addressType Address type to generate
         * @returns Derived key information
         */
        deriveChildKey(
            account: number,
            change: number,
            addressIndex: number,
            addressType: AddressType
        ): DerivedKey;
    }

    /**
     * Non-custodial wallet with threshold signature support
     */
    export class NonCustodialWallet {
        /**
         * Create a new non-custodial wallet
         * @param network Bitcoin network to use
         * @param participants Total number of participants
         * @param threshold Minimum signatures required
         * @param seed Optional seed for deterministic generation
         */
        constructor(
            network: BitcoinNetwork,
            participants: number,
            threshold: number,
            seed?: BufferLike
        );

        /**
         * Generate threshold signature shares
         * @param message Message to sign
         * @returns Array of signature shares
         */
        generateSignatureShares(message: string): PolynomialShare[];

        /**
         * Combine signature shares into final signature
         * @param shares Array of signature shares
         * @returns Complete threshold signature
         */
        combineSignatureShares(shares: PolynomialShare[]): ThresholdSignatureResult;

        /**
         * Derive a child key at the specified path
         * @param account Account index
         * @param change Change type (0=external, 1=internal)
         * @param addressIndex Address index
         * @param addressType Address type to generate
         * @returns Derived key information
         */
        deriveChildKey(
            account: number,
            change: number,
            addressIndex: number,
            addressType: AddressType
        ): DerivedKey;

        /**
         * Get threshold configuration
         * @returns Threshold parameters
         */
        getThresholdConfig(): { participants: number; threshold: number };
    }

    // =============================================================================
    // BIP IMPLEMENTATIONS
    // =============================================================================

    /**
     * BIP39 mnemonic phrase utilities
     */
    export class BIP39 {
        /**
         * Generate a new mnemonic phrase
         * @param strength Entropy strength in bits (128, 160, 192, 224, 256)
         * @returns Generated mnemonic phrase
         */
        static generate(strength?: 128 | 160 | 192 | 224 | 256): string;

        /**
         * Validate a mnemonic phrase
         * @param mnemonic Mnemonic phrase to validate
         * @returns True if valid, false otherwise
         */
        static validate(mnemonic: string): boolean;

        /**
         * Convert mnemonic to seed
         * @param mnemonic Mnemonic phrase
         * @param passphrase Optional passphrase
         * @returns Seed bytes
         */
        static toSeed(mnemonic: string, passphrase?: string): Uint8Array;

        /**
         * Convert mnemonic to entropy
         * @param mnemonic Mnemonic phrase
         * @returns Entropy bytes
         */
        static toEntropy(mnemonic: string): Uint8Array;

        /**
         * Convert entropy to mnemonic
         * @param entropy Entropy bytes
         * @returns Mnemonic phrase
         */
        static fromEntropy(entropy: BufferLike): string;
    }

    /**
     * BECH32 address encoding/decoding (BIP173/BIP350)
     */
    export class BECH32 {
        /**
         * Encode data using Bech32
         * @param prefix Human-readable prefix
         * @param data Data to encode
         * @returns Bech32 encoded string
         */
        static encode(prefix: string, data: Uint8Array): string;

        /**
         * Decode Bech32 encoded string
         * @param address Bech32 encoded string
         * @returns Decoded data with prefix
         */
        static decode(address: string): { prefix: string; data: Uint8Array };

        /**
         * Validate Bech32 address
         * @param address Address to validate
         * @returns True if valid, false otherwise
         */
        static validate(address: string): boolean;
    }

    // =============================================================================
    // CRYPTOGRAPHY CLASSES
    // =============================================================================

    /**
     * ECDSA signature implementation
     */
    export class ECDSA {
        /**
         * Sign a message hash using ECDSA
         * @param messageHash Hash to sign
         * @param privateKey Private key for signing
         * @returns ECDSA signature
         */
        static sign(messageHash: Uint8Array, privateKey: Uint8Array): ECDSASignature;

        /**
         * Verify an ECDSA signature
         * @param signature Signature to verify
         * @param messageHash Original message hash
         * @param publicKey Public key for verification
         * @returns True if signature is valid
         */
        static verify(
            signature: ECDSASignature,
            messageHash: Uint8Array,
            publicKey: Uint8Array
        ): boolean;

        /**
         * Recover public key from signature
         * @param signature Signature with recovery info
         * @param messageHash Original message hash
         * @returns Recovered public key
         */
        static recoverPublicKey(
            signature: ECDSASignature & { recovery: number },
            messageHash: Uint8Array
        ): Uint8Array;
    }

    /**
     * Schnorr signature implementation (BIP340)
     */
    export class SchnorrSignature {
        /**
         * Sign a message using Schnorr signatures
         * @param message Message to sign
         * @param privateKey Private key for signing
         * @returns Schnorr signature
         */
        static sign(message: Uint8Array, privateKey: Uint8Array): SchnorrSignature;

        /**
         * Verify a Schnorr signature
         * @param signature Signature to verify
         * @param message Original message
         * @param publicKey Public key for verification
         * @returns True if signature is valid
         */
        static verify(
            signature: Uint8Array,
            message: Uint8Array,
            publicKey: Uint8Array
        ): boolean;

        /**
         * Aggregate multiple Schnorr signatures
         * @param signatures Array of signatures to aggregate
         * @returns Aggregated signature
         */
        static aggregate(signatures: Uint8Array[]): Uint8Array;
    }

    /**
     * Polynomial implementation for threshold cryptography
     */
    export class Polynomial {
        /** Polynomial degree */
        readonly degree: number;

        /** Polynomial coefficients */
        readonly coefficients: bigint[];

        /**
         * Create a new polynomial
         * @param coefficients Polynomial coefficients
         */
        constructor(coefficients: bigint[]);

        /**
         * Evaluate polynomial at given x value
         * @param x X-coordinate
         * @returns Y-coordinate (polynomial evaluation)
         */
        evaluate(x: bigint): bigint;

        /**
         * Generate shares for secret sharing
         * @param numShares Number of shares to generate
         * @returns Array of polynomial shares
         */
        generateShares(numShares: number): PolynomialShare[];

        /**
         * Interpolate polynomial from shares
         * @param shares Polynomial shares
         * @returns Reconstructed secret (constant term)
         */
        static interpolate(shares: PolynomialShare[]): bigint;

        /**
         * Generate random polynomial with given secret and degree
         * @param secret Secret value (constant term)
         * @param degree Polynomial degree
         * @returns Random polynomial
         */
        static random(secret: bigint, degree: number): Polynomial;
    }

    /**
     * Threshold signature implementation
     */
    export class ThresholdSignature {
        /** Number of participants */
        readonly participants: number;

        /** Minimum threshold required */
        readonly threshold: number;

        /** Polynomial shares */
        readonly shares: PolynomialShare[];

        /**
         * Create threshold signature scheme
         * @param participants Total number of participants
         * @param threshold Minimum signatures required
         * @param secret Optional secret key
         */
        constructor(participants: number, threshold: number, secret?: bigint);

        /**
         * Generate signature for a message
         * @param message Message to sign
         * @returns Threshold signature result
         */
        sign(message: string): ThresholdSignatureResult;

        /**
         * Verify threshold signature
         * @param publicKey Public key for verification
         * @param messageHash Message hash
         * @param signature Signature to verify
         * @returns True if signature is valid
         */
        static verifyThresholdSignature(
            publicKey: any,
            messageHash: Uint8Array,
            signature: { r: bigint; s: bigint }
        ): boolean;

        /**
         * Combine partial signatures
         * @param partialSignatures Array of partial signatures
         * @returns Combined signature
         */
        combineSignatures(partialSignatures: PolynomialShare[]): ThresholdSignatureResult;
    }

    // =============================================================================
    // UTILITY FUNCTIONS
    // =============================================================================

    /**
     * Generate master key from seed (BIP32)
     * @param seed Seed bytes for key generation
     * @param network Bitcoin network
     * @returns Master key pair
     */
    export function fromSeed(seed: BufferLike, network?: BitcoinNetwork): HDKeys;

    /**
     * Alternative name for fromSeed
     */
    export const generateMasterKey: typeof fromSeed;

    /**
     * Derive child key from parent (BIP32)
     * @param parentKey Parent extended key
     * @param derivationPath Child derivation path
     * @param network Bitcoin network
     * @returns Derived child key
     */
    export function derive(
        parentKey: string,
        derivationPath: string,
        network?: BitcoinNetwork
    ): HDKeys;

    /**
     * Generate BIP44 derivation path
     * @param options Path generation options
     * @returns Complete BIP44 derivation path
     */
    export function generateDerivationPath(options?: DerivationPathOptions): string;

    /**
     * Parse derivation path into components
     * @param path Derivation path to parse
     * @returns Parsed path components
     */
    export function parseDerivationPath(path: string): ParsedDerivationPath;

    /**
     * Validate Bitcoin derivation path
     * @param path Path to validate
     * @returns True if valid for Bitcoin
     */
    export function isValidBitcoinPath(path: string): boolean;

    /**
     * Get network configuration by coin type
     * @param coinType BIP44 coin type
     * @returns Network configuration
     */
    export function getNetworkByCoinType(coinType: 0 | 1): NetworkConfig;

    // =============================================================================
    // ENCODING FUNCTIONS
    // =============================================================================

    /**
     * Base58Check encode data
     * @param data Data to encode
     * @returns Base58Check encoded string
     */
    export function b58encode(data: BufferLike): string;

    /**
     * Base58Check decode string
     * @param encoded Encoded string to decode
     * @returns Decoded data
     */
    export function b58decode(encoded: string): Uint8Array;

    /**
     * Generate HD key in standard format
     * @param keyType Type of key (private or public)
     * @param keyData Key data and metadata
     * @returns Formatted HD key
     */
    export function hdKey(keyType: KeyType, keyData: any): string;

    /**
     * Generate standard key pair
     * @param privateKey Private key information
     * @param publicKey Public key information
     * @returns Standard key pair
     */
    export function standardKey(privateKey: any, publicKey: any): KeyPair;

    /**
     * Generate Bitcoin address from public key
     * @param versionByte Address version byte
     * @param publicKey Public key buffer
     * @returns Bitcoin address
     */
    export function address(versionByte: number, publicKey: BufferLike): string;

    /**
     * RIPEMD160 hash function
     * @param data Data to hash
     * @returns RIPEMD160 hash
     */
    export function rmd160(data: BufferLike): Uint8Array;

    /**
     * Decode WIF private key
     * @param wifKey WIF encoded private key
     * @returns Raw private key bytes
     */
    export function privateKeyDecode(wifKey: string): Uint8Array;

    /**
     * Decode legacy Bitcoin address
     * @param address Legacy address to decode
     * @returns Hash160 bytes
     */
    export function legacyAddressDecode(address: string): Uint8Array;

    // =============================================================================
    // CONFIGURATION CONSTANTS
    // =============================================================================

    /**
     * Library feature support matrix
     */
    export const FEATURES: Readonly<{
        /** Hierarchical Deterministic Wallets (BIP32) */
        HD_WALLETS: boolean;
        /** Threshold Signature Schemes */
        THRESHOLD_SIGNATURES: boolean;
        /** ECDSA Signatures */
        ECDSA: boolean;
        /** Schnorr Signatures (BIP340) */
        SCHNORR: boolean;
        /** Pay-to-Public-Key-Hash (Legacy) */
        P2PKH: boolean;
        /** Pay-to-Witness-Public-Key-Hash (SegWit) */
        P2WPKH: boolean;
        /** Pay-to-Script-Hash */
        P2SH: boolean;
        /** Pay-to-Witness-Script-Hash */
        P2WSH: boolean;
        /** Pay-to-Taproot (BIP341) */
        P2TR: boolean;
        /** Transaction Building and Broadcasting */
        TRANSACTIONS: boolean;
        /** Simplified Payment Verification */
        SPV: boolean;
        /** Lightning Network */
        LIGHTNING: boolean;
    }>;

    /**
     * Supported Bitcoin networks
     */
    export const NETWORKS: Readonly<{
        /** Bitcoin Mainnet */
        BTC_MAIN: NetworkConfig;
        /** Bitcoin Testnet */
        BTC_TEST: NetworkConfig;
    }>;

    /**
     * Library version and metadata
     */
    export const LIBRARY_INFO: Readonly<{
        name: string;
        version: string;
        description: string;
        author: string;
        license: string;
        repository: string;
    }>;

    /**
     * BIP compliance matrix
     */
    export const BIP_COMPLIANCE: Readonly<{
        /** Hierarchical Deterministic Wallets */
        BIP32: boolean;
        /** Mnemonic code for generating deterministic keys */
        BIP39: boolean;
        /** Multi-Account Hierarchy for Deterministic Wallets */
        BIP44: boolean;
        /** Derivation scheme for P2WPKH-nested-in-P2SH */
        BIP49: boolean;
        /** Derivation scheme for P2WPKH */
        BIP84: boolean;
        /** Key Derivation for Single Key P2TR Outputs */
        BIP86: boolean;
        /** Segregated Witness (Consensus layer) */
        BIP141: boolean;
        /** Transaction Signature Verification for Version 0 Witness Program */
        BIP143: boolean;
        /** Base32 address format for native v0-16 witness outputs */
        BIP173: boolean;
        /** Schnorr Signatures for secp256k1 */
        BIP340: boolean;
        /** Taproot: SegWit version 1 spending rules */
        BIP341: boolean;
        /** Validation of Taproot Scripts */
        BIP342: boolean;
        /** Base32 address format for native v1+ witness outputs */
        BIP350: boolean;
    }>;

    // =============================================================================
    // LEGACY ALIASES (DEPRECATED)
    // =============================================================================

    /**
     * @deprecated Use CustodialWallet instead
     */
    export const Custodial_Wallet: typeof CustodialWallet;

    /**
     * @deprecated Use NonCustodialWallet instead
     */
    export const Non_Custodial_Wallet: typeof NonCustodialWallet;

    /**
     * @deprecated Use ECDSA instead
     */
    export const ecdsa: typeof ECDSA;

    /**
     * @deprecated Use SchnorrSignature instead
     */
    export const schnorr_sig: typeof SchnorrSignature;

    // =============================================================================
    // DEFAULT EXPORT
    // =============================================================================

    /**
     * Default export containing all major components
     */
    const JBitcoin: {
        // Wallets
        CustodialWallet: typeof CustodialWallet;
        NonCustodialWallet: typeof NonCustodialWallet;

        // Cryptography
        ECDSA: typeof ECDSA;
        SchnorrSignature: typeof SchnorrSignature;
        Polynomial: typeof Polynomial;
        ThresholdSignature: typeof ThresholdSignature;

        // BIP implementations
        BIP39: typeof BIP39;
        BECH32: typeof BECH32;
        fromSeed: typeof fromSeed;
        derive: typeof derive;

        // Configuration
        FEATURES: typeof FEATURES;
        NETWORKS: typeof NETWORKS;
        LIBRARY_INFO: typeof LIBRARY_INFO;
        BIP_COMPLIANCE: typeof BIP_COMPLIANCE;
    };

    export default JBitcoin;
}

// =============================================================================
// GLOBAL DECLARATIONS
// =============================================================================

declare global {
    namespace JBitcoin {
        export type Network = BitcoinNetwork;
        export type Address = AddressType;
        export type Purpose = BIPPurpose;
    }
}

export = JBitcoin;
export as namespace JBitcoin;