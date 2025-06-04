/**
 * J-Bitcoin - Comprehensive TypeScript definitions
 * 
 * Complete type definitions for Bitcoin
 * cryptocurrency wallet library with custodial and non-custodial support.
 * 
 * @version 1.0.0
 * @author yfbsei
 */

declare module 'j-bitcoin' {
    // ============================================================================
    // CORE TYPES AND INTERFACES
    // ============================================================================

    /** Network type for Bitcoin-based cryptocurrencies */
    type NetworkType = 'main' | 'test';

    /** Key derivation type for BIP32 hierarchical deterministic wallets */
    type KeyType = 'pri' | 'pub';

    /** Address type for different Bitcoin script formats */
    type AddressType = 'p2pkh' | 'p2sh';

    /** Bech32 encoding type for SegWit addresses */
    type Bech32Encoding = 'bech32' | 'bech32m';

    // ============================================================================
    // WALLET INTERFACES
    // ============================================================================

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

    /** Child key information with derivation metadata */
    interface ChildKeyInfo {
        /** Derivation depth in the HD tree */
        depth: number;
        /** Index of this child key */
        childIndex: number;
        /** HD key pair for this child */
        hdKey: HDKeys;
        /** Standard key pair for this child */
        keypair: KeyPair;
        /** Bitcoin address for this child key */
        address: string;
    }

    /** ECDSA signature result with recovery information */
    interface ECDSASignatureResult {
        /** DER-encoded signature bytes */
        0: Uint8Array;
        /** Recovery ID for public key recovery (0-3) */
        1: number;
    }

    /** Threshold signature result with metadata */
    interface ThresholdSignatureResult {
        /** Signature object with r and s values */
        sig: {
            r: bigint;
            s: bigint;
        };
        /** Base64-encoded compact signature format */
        serialized_sig: string;
        /** SHA256 hash of the signed message */
        msgHash: Buffer;
        /** Recovery ID for public key recovery (0-3) */
        recovery_id: number;
    }

    /** BIP39 mnemonic and seed generation result */
    interface MnemonicResult {
        /** 12-word mnemonic phrase */
        mnemonic: string;
        /** Hex-encoded 64-byte seed derived from mnemonic */
        seed: string;
    }

    // ============================================================================
    // CUSTODIAL WALLET CLASS
    // ============================================================================

    /**
     * Custodial wallet implementation supporting hierarchical deterministic key derivation
     * and standard ECDSA signatures. Suitable for single-party control scenarios.
     */
    export class Custodial_Wallet {
        /** Network type ('main' or 'test') */
        readonly net: NetworkType;
        /** Hierarchical deterministic key pair */
        readonly hdKey: HDKeys;
        /** Standard key pair (WIF private key and hex public key) */
        readonly keypair: KeyPair;
        /** Bitcoin address for this wallet */
        readonly address: string;
        /** Set of derived child keys */
        child_keys: Set<ChildKeyInfo>;

        /**
         * Creates a new Custodial_Wallet instance
         * @param net Network type ('main' for mainnet, 'test' for testnet)
         * @param master_keys Master key information
         * @param serialization_format Internal serialization format for key derivation
         */
        constructor(net: NetworkType, master_keys: any, serialization_format: any);

        /**
         * Generates a new random wallet with mnemonic phrase
         * @param net Network type ('main' or 'test')
         * @param passphrase Optional passphrase for additional security
         * @returns Tuple of [mnemonic phrase, wallet instance]
         */
        static fromRandom(net?: NetworkType, passphrase?: string): [string, Custodial_Wallet];

        /**
         * Creates a wallet from an existing mnemonic phrase
         * @param net Network type ('main' or 'test')
         * @param mnemonic 12-word mnemonic phrase
         * @param passphrase Optional passphrase used during generation
         * @returns New wallet instance
         * @throws Error if mnemonic has invalid checksum
         */
        static fromMnemonic(net?: NetworkType, mnemonic?: string, passphrase?: string): Custodial_Wallet;

        /**
         * Creates a wallet from a hex-encoded seed
         * @param net Network type ('main' or 'test')
         * @param seed Hex-encoded seed
         * @returns New wallet instance
         */
        static fromSeed(net?: NetworkType, seed?: string): Custodial_Wallet;

        /**
         * Derives a child key from the current wallet using BIP32 derivation path
         * @param path BIP32 derivation path (e.g., "m/0'/1/2")
         * @param keyType Key type to derive ('pri' for private, 'pub' for public)
         * @returns Returns this wallet instance for method chaining
         * @throws Error if trying to derive hardened path from public key
         */
        derive(path?: string, keyType?: KeyType): this;

        /**
         * Signs a message using ECDSA with the wallet's private key
         * @param message Message to sign
         * @returns Tuple of [signature bytes, recovery ID]
         */
        sign(message?: string): ECDSASignatureResult;

        /**
         * Verifies an ECDSA signature against a message using the wallet's public key
         * @param sig Signature to verify
         * @param msg Original message that was signed
         * @returns True if signature is valid, false otherwise
         */
        verify(sig: Uint8Array | Buffer, msg: string): boolean;
    }

    // ============================================================================
    // NON-CUSTODIAL WALLET CLASS
    // ============================================================================

    /**
     * Non-custodial wallet implementation using Threshold Signature Scheme (TSS)
     * for distributed key management. Enables multi-party control without a trusted party.
     */
    export class Non_Custodial_Wallet {
        /** Network type ('main' or 'test') */
        readonly net: NetworkType;
        /** Total number of participants in the threshold scheme */
        readonly group_size: number;
        /** Minimum number of participants required to sign */
        readonly threshold: number;
        /** Hex-encoded compressed public key */
        readonly publicKey: string;
        /** Bitcoin address for this threshold wallet */
        readonly address: string;

        /**
         * Creates a new Non_Custodial_Wallet instance
         * @param net Network type ('main' for mainnet, 'test' for testnet)
         * @param group_size Total number of participants in the threshold scheme
         * @param threshold Minimum number of participants required to sign
         */
        constructor(net: NetworkType, group_size: number, threshold: number);

        /**
         * Generates a new random threshold wallet
         * @param net Network type ('main' or 'test')
         * @param group_size Total number of participants
         * @param threshold Minimum participants required for signing
         * @returns New threshold wallet instance
         * @throws Error if threshold is greater than group_size or less than 2
         */
        static fromRandom(net?: NetworkType, group_size?: number, threshold?: number): Non_Custodial_Wallet;

        /**
         * Reconstructs a threshold wallet from existing shares
         * @param net Network type ('main' or 'test')
         * @param shares Array of hex-encoded secret shares
         * @param threshold Minimum participants required for signing
         * @returns Reconstructed wallet instance
         */
        static fromShares(net?: NetworkType, shares: string[], threshold?: number): Non_Custodial_Wallet;

        /**
         * Gets the secret shares as hex strings for distribution to participants
         * @returns Array of hex-encoded secret shares
         */
        get _shares(): string[];

        /**
         * Gets the reconstructed private key in WIF format
         * @returns WIF-encoded private key
         */
        get _privateKey(): string;

        /**
         * Generates a threshold signature for a given message
         * @param message Message to sign (will be SHA256 hashed)
         * @returns Complete signature with metadata
         */
        sign(message: string): ThresholdSignatureResult;

        /**
         * Verifies a threshold signature against the original message hash
         * @param sig Signature object with r and s properties
         * @param msgHash SHA256 hash of the original message
         * @returns True if signature is valid, false otherwise
         */
        verify(sig: { r: bigint; s: bigint }, msgHash: Buffer): boolean;
    }

    // ============================================================================
    // BIP39 MNEMONIC UTILITIES
    // ============================================================================

    export namespace bip39 {
        /**
         * Generates a random 12-word mnemonic phrase using cryptographically secure entropy
         * @returns Space-separated 12-word mnemonic phrase
         */
        function mnemonic(): string;

        /**
         * Derives a cryptographic seed from a mnemonic phrase using PBKDF2
         * @param mnemonic Space-separated mnemonic phrase
         * @param passphrase Optional passphrase for additional security
         * @returns Hex-encoded 64-byte (512-bit) seed
         */
        function seed(mnemonic?: string, passphrase?: string): string;

        /**
         * Validates the checksum of a BIP39 mnemonic phrase
         * @param mnemonic Space-separated mnemonic phrase to validate
         * @returns True if checksum is valid, false otherwise
         */
        function checkSum(mnemonic?: string): boolean;

        /**
         * Generates a random mnemonic with validated checksum and derives its seed
         * @param passphrase Optional passphrase for seed derivation
         * @returns Object containing both mnemonic and seed
         * @throws Error if generated mnemonic fails validation
         */
        function random(passphrase?: string): MnemonicResult;

        /**
         * Converts a mnemonic phrase to a seed with checksum validation
         * @param mnemonic Space-separated mnemonic phrase
         * @param passphrase Optional passphrase for additional security
         * @returns Hex-encoded 64-byte seed
         * @throws Error if mnemonic validation fails
         */
        function mnemonic2seed(mnemonic?: string, passphrase?: string): string;
    }

    // ============================================================================
    // SIGNATURE ALGORITHMS
    // ============================================================================

    export namespace ecdsa {
        /**
         * Signs a message using ECDSA with deterministic k-value generation (RFC 6979)
         * @param private_key WIF-encoded private key
         * @param msg Message to sign (will be UTF-8 encoded)
         * @returns Tuple of [signature bytes, recovery ID]
         */
        function sign(private_key?: string, msg?: string): ECDSASignatureResult;

        /**
         * Verifies an ECDSA signature against a message using a public key
         * @param sig DER-encoded signature bytes
         * @param msg Original message that was signed
         * @param public_key Compressed or uncompressed public key
         * @returns True if signature is valid, false otherwise
         */
        function verify(sig: Uint8Array | Buffer, msg?: string, public_key: Uint8Array | Buffer): boolean;

        /**
         * Recovers the public key from a signature and message using the recovery ID
         * @param msg Original message that was signed
         * @param sig DER-encoded signature bytes
         * @param recovery Recovery ID (0-3) obtained during signing
         * @returns Compressed public key (33 bytes)
         */
        function retrieve_public_key(msg?: string, sig: Uint8Array | Buffer, recovery?: number): Uint8Array;
    }

    export namespace schnorr_sig {
        /**
         * Creates a Schnorr signature for a given message using BIP340 specification
         * @param private_key WIF-encoded private key
         * @param msg Message to sign (will be UTF-8 encoded)
         * @param auxRand 32 bytes of auxiliary randomness for nonce generation
         * @returns 64-byte Schnorr signature (32-byte R.x + 32-byte s)
         */
        function sign(private_key?: string, msg?: string, auxRand?: Uint8Array): Uint8Array;

        /**
         * Verifies a Schnorr signature against a message and public key
         * @param sig 64-byte Schnorr signature to verify
         * @param msg Original message that was signed
         * @param public_key 32-byte x-only public key (BIP340 format)
         * @returns True if signature is valid, false otherwise
         */
        function verify(sig: Uint8Array | Buffer, msg?: string, public_key: Uint8Array | Buffer): boolean;

        /**
         * Derives the Schnorr public key from a private key according to BIP340
         * @param private_key WIF-encoded private key
         * @returns 32-byte x-only public key for use with Schnorr signatures
         */
        function retrieve_public_key(private_key?: string): Uint8Array;
    }

    // ============================================================================
    // ADDRESS FORMAT UTILITIES
    // ============================================================================

    export namespace BECH32 {
        /**
         * Converts a legacy Bitcoin address to a P2WPKH (Pay to Witness PubKey Hash) Bech32 address
         * @param witness_program Legacy P2PKH address to convert
         * @returns Bech32-encoded P2WPKH address
         * @throws Error if the legacy address is invalid or has wrong format
         */
        function to_P2WPKH(witness_program?: string): string;

        /**
         * Encodes arbitrary hex data into a Bech32 address with custom prefix
         * @param prefix Custom Human Readable Part for the address
         * @param data Hex-encoded data to include in the address
         * @param encoding Encoding type: 'bech32' or 'bech32m'
         * @returns Bech32-encoded address with custom prefix and data
         * @throws Error if the total address length would exceed 90 characters
         */
        function data_to_bech32(prefix?: string, data?: string, encoding?: Bech32Encoding): string;
    }

    // ============================================================================
    // BIP32 UTILITIES
    // ============================================================================

    /**
     * Generates BIP32 master keys from a cryptographic seed
     * @param seed Hex-encoded cryptographic seed (typically 128-512 bits from BIP39)
     * @param net Network type: 'main' for Bitcoin mainnet, 'test' for testnet
     * @returns Tuple containing [HD key pair, serialization format]
     */
    export function fromSeed(seed: string, net?: NetworkType): [HDKeys, any];

    /**
     * Derives child keys from parent keys using BIP32 hierarchical deterministic algorithm
     * @param path BIP32 derivation path (e.g., "m/44'/0'/0'/0/0")
     * @param key Parent extended key in xprv/xpub or tprv/tpub format
     * @param serialization_format Parent key's serialization metadata
     * @returns Tuple of [derived keys, child serialization format]
     */
    export function derive(path: string, key?: string, serialization_format?: any): [HDKeys, any];

    // ============================================================================
    // THRESHOLD SIGNATURE COMPONENTS
    // ============================================================================

    /**
     * Polynomial class for finite field arithmetic over secp256k1 curve order
     */
    export class Polynomial {
        /** Polynomial degree (highest power of x) */
        readonly order: number;
        /** Array of polynomial coefficients as BigNumbers */
        readonly coefficients: any[];

        /**
         * Creates a polynomial with given coefficients
         * @param coefficients Array of BigNumber coefficients from constant to highest degree
         */
        constructor(coefficients: any[]);

        /**
         * Generates a random polynomial of specified degree using cryptographically secure randomness
         * @param order Degree of the polynomial to generate
         * @returns New polynomial with random coefficients
         */
        static fromRandom(order?: number): Polynomial;

        /**
         * Reconstructs a secret using Lagrange interpolation from coordinate points
         * @param points Array of [x, y] coordinate pairs
         * @param x Point at which to evaluate the interpolated polynomial
         * @returns The interpolated value f(x) modulo curve order
         */
        static interpolate_evaluate(points?: [number, any][], x?: number): any;

        /**
         * Evaluates the polynomial at a given point using Horner's method
         * @param x Point at which to evaluate the polynomial
         * @returns The polynomial value f(x) modulo curve order
         */
        evaluate(x?: number): any;

        /**
         * Adds two polynomials coefficient-wise
         * @param other Polynomial to add
         * @returns New polynomial representing the sum
         */
        add(other?: Polynomial): Polynomial;

        /**
         * Multiplies two polynomials using convolution
         * @param other Polynomial to multiply
         * @returns New polynomial representing the product
         */
        multiply(other?: Polynomial): Polynomial;
    }

    /**
     * Threshold Signature Scheme implementation for distributed cryptography
     */
    export class ThresholdSignature {
        /** Total number of participants */
        readonly group_size: number;
        /** Polynomial degree (threshold - 1) */
        readonly polynomial_order: number;
        /** Minimum participants needed for operations */
        readonly threshold: number;

        /**
         * Creates a new threshold signature scheme
         * @param group_size Total number of participants in the scheme
         * @param threshold Minimum number of participants needed to create signatures
         */
        constructor(group_size?: number, threshold?: number);

        /**
         * Converts share values to coordinate points for polynomial interpolation
         * @param shares Array of BigNumber share values
         * @returns Array of [x, y] points for interpolation
         */
        shares_to_points(shares?: any[]): [number, any][];

        /**
         * Joint Verifiable Random Secret Sharing (JVRSS) protocol implementation
         * @returns Tuple of [secret shares array, aggregate public key]
         */
        jvrss(): [any[], any];

        /**
         * Additive Secret Sharing (ADDSS) - combines two sets of shares additively
         * @param a_shares First set of secret shares
         * @param b_shares Second set of secret shares
         * @returns The sum of the two original secrets
         */
        addss(a_shares?: any[], b_shares?: any[]): any;

        /**
         * Multiplicative Secret Sharing (PROSS) - computes product of shared secrets
         * @param a_shares First set of secret shares
         * @param b_shares Second set of secret shares
         * @returns The product of the two original secrets
         */
        pross(a_shares?: any[], b_shares?: any[]): any;

        /**
         * Inverse Secret Sharing (INVSS) - computes modular inverse of shared secret
         * @param a_shares Shares of the secret to invert
         * @returns Shares of the modular inverse of the original secret
         */
        invss(a_shares?: any[]): any[];

        /**
         * Reconstructs the private key from secret shares using polynomial interpolation
         * @param a_shares Secret shares to reconstruct from (defaults to this.shares)
         * @returns The reconstructed private key
         */
        privite_key(a_shares?: any[]): any;

        /**
         * Generates a threshold signature for a given message
         * @param message Message to sign (will be SHA256 hashed)
         * @returns Complete signature with metadata
         */
        sign(message: string): ThresholdSignatureResult;

        /**
         * Verifies a threshold signature against a public key and message hash
         * @param public_key Elliptic curve public key point
         * @param msgHash SHA256 hash of the original message
         * @param sig Signature object with r and s components
         * @returns True if signature is valid, false otherwise
         */
        static verify_threshold_signature(public_key: any, msgHash: Buffer, sig: { r: bigint; s: bigint }): boolean;
    }

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    /**
     * Base58Check encoding for Bitcoin addresses and keys
     * @param data Data to encode
     * @returns Base58Check encoded string
     */
    export function b58encode(data: Buffer): string;

    /**
     * Generates hierarchical deterministic keys in standard format
     * @param keyType 'pri' for private key, 'pub' for public key
     * @param format Key serialization format
     * @returns Formatted HD key (xprv/xpub)
     */
    export function hdKey(keyType: KeyType, format: any): string;

    /**
     * Generates standard format private/public key pair
     * @param privKey Private key information
     * @param pubKey Public key information
     * @returns Standard key pair {pri, pub}
     */
    export function standardKey(privKey: any, pubKey: any): KeyPair;

    /**
     * Generates Bitcoin address from public key
     * @param versionByte Address version byte
     * @param pubKey Public key buffer
     * @returns Bitcoin address
     */
    export function address(versionByte: number, pubKey: Buffer): string;

    /**
     * RIPEMD160 hash function implementation
     * @param data Data to hash
     * @returns RIPEMD160 hash result
     */
    export function rmd160(data: Buffer | Uint8Array | ArrayBuffer): Buffer;

    /**
     * Decodes WIF (Wallet Import Format) private keys
     * @param priKey WIF-encoded private key
     * @returns Raw private key bytes
     */
    export function privateKey_decode(priKey?: string): Uint8Array;

    /**
     * Decodes legacy Bitcoin addresses to extract hash160
     * @param address Legacy Bitcoin address
     * @returns Hash160 bytes
     */
    export function legacyAddress_decode(address?: string): Uint8Array;

    // ============================================================================
    // CONSTANTS AND FEATURE FLAGS
    // ============================================================================

    /** Library feature support matrix */
    export const FEATURES: {
        /** Hierarchical Deterministic Wallets (BIP32) */
        HD_WALLETS: boolean;
        /** Threshold Signature Schemes */
        THRESHOLD_SIGNATURES: boolean;
        /** ECDSA Signatures */
        ECDSA: boolean;
        /** Schnorr Signatures (BIP340) */
        SCHNORR: boolean;
        /** P2PKH Legacy Addresses */
        P2PKH: boolean;
        /** P2WPKH SegWit Addresses */
        P2WPKH: boolean;
        /** P2SH Script Hash Addresses */
        P2SH: boolean;
        /** P2WSH SegWit Script Hash */
        P2WSH: boolean;
        /** Transaction Building */
        TRANSACTIONS: boolean;
        /** SPV (Simplified Payment Verification) */
        SPV: boolean;
    };

    /** Supported cryptocurrency networks */
    export const NETWORKS: {
        /** Bitcoin mainnet */
        BTC_MAIN: { name: string; symbol: string; network: string };
        /** Bitcoin testnet */
        BTC_TEST: { name: string; symbol: string; network: string };
    };
}

export = j_bitcoin;
export as namespace j_bitcoin;