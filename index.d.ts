/**
 * J-Bitcoin - TypeScript Definitions
 * @version 3.0.0
 * @author yfbsei
 * @license ISC
 */

declare module 'j-bitcoin' {
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // CORE TYPES
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** Bitcoin network type */
    export type BitcoinNetwork = 'main' | 'test';

    /** Address format types */
    export type AddressType = 'legacy' | 'segwit' | 'taproot';

    /** BIP derivation purposes */
    export type BIPPurpose = 44 | 49 | 84 | 86;

    /** Buffer-like input types */
    export type BufferLike = Buffer | Uint8Array | ArrayBuffer;

    /** BN.js compatible type */
    export type BNLike = any;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // INTERFACES
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** Network configuration */
    export interface NetworkConfig {
        name: string;
        symbol: string;
        network: BitcoinNetwork;
        chainId: number;
        bip44CoinType: 0 | 1;
    }

    /** HD key pair (extended keys) */
    export interface HDKeys {
        extendedPrivateKey: string;
        extendedPublicKey: string;
    }

    /** Derived address result */
    export interface DerivedAddress {
        address: string;
        publicKey: string;
        privateKey: string | null;
        path: string;
        type: AddressType;
        network: BitcoinNetwork;
    }

    /** ECDSA signature components */
    export interface ECDSASignature {
        r: bigint;
        s: bigint;
        recovery?: number;
    }

    /** Threshold signature result */
    export interface ThresholdSignatureResult {
        r: string;
        s: string;
        signature: Buffer;
    }

    /** Participant share for threshold signatures (nChain TSS) */
    export interface ParticipantShareData {
        index: number;
        keyShare: string;
        publicKeyShare?: string | null;
    }

    /** Threshold scheme configuration */
    export interface ThresholdConfig {
        n: number;
        t: number;
        reconstructionThreshold: number;
        signingThreshold: number;
        sharesAvailable: number;
        ephemeralKeysAvailable?: number;
    }

    /** Share for interpolation */
    export interface InterpolationShare {
        x: BNLike;
        y: BNLike;
    }

    /** UTXO structure */
    export interface UTXO {
        txid: string;
        vout: number;
        value: number;
        scriptPubKey: string;
        address?: string;
    }

    /** Transaction structure */
    export interface Transaction {
        version: number;
        inputs: Array<{
            txid: string;
            vout: number;
            scriptSig: string;
            sequence?: number;
        }>;
        outputs: Array<{
            value: number;
            scriptPubKey: string;
            address?: string;
        }>;
        locktime: number;
        txid?: string;
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // WALLET CLASSES
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** Wallet error with solution hint */
    export class CustodialWalletError extends Error {
        name: 'CustodialWalletError';
        solution: string;
        timestamp: string;
        constructor(message: string, solution?: string);
    }

    /** Custodial HD wallet implementation */
    export class CustodialWallet {
        readonly network: BitcoinNetwork;
        readonly version: string;
        readonly created: number;

        constructor(network: BitcoinNetwork, masterKeys: HDKeys, mnemonic?: string | null);

        /** Create a new wallet with generated mnemonic */
        static createNew(network?: BitcoinNetwork): { wallet: CustodialWallet; mnemonic: string };

        /** Restore wallet from mnemonic phrase */
        static fromMnemonic(network: BitcoinNetwork, mnemonic: string): CustodialWallet;

        /** Create wallet from raw seed */
        static fromSeed(network: BitcoinNetwork, seed: BufferLike): CustodialWallet;

        /** Create wallet from extended key (xprv/xpub/tprv/tpub) */
        static fromExtendedKey(network: BitcoinNetwork, extendedKey: string): CustodialWallet;

        /** Derive address at specific path */
        deriveAddress(account?: number, change?: number, index?: number, type?: AddressType): DerivedAddress;

        /** Get receiving address (change=0) */
        getReceivingAddress(account?: number, index?: number, type?: AddressType): DerivedAddress;

        /** Get change address (change=1) */
        getChangeAddress(account?: number, index?: number, type?: AddressType): DerivedAddress;

        /** Sign message with derived key */
        signMessage(message: string, account?: number, index?: number): ECDSASignature;

        /** Verify message signature */
        verifyMessage(message: string, signature: ECDSASignature, publicKey: string): boolean;

        /** Get master extended public key */
        getExtendedPublicKey(): string;

        /** Get master extended private key */
        getExtendedPrivateKey(): string;

        /** Get mnemonic phrase (if available) */
        getMnemonic(): string | null;

        /** Get network type */
        getNetwork(): BitcoinNetwork;

        /** Export wallet info (without private keys) */
        toJSON(): {
            network: BitcoinNetwork;
            version: string;
            created: number;
            extendedPublicKey: string;
            addressCount: number;
        };

        /** Clear derived address cache */
        clearCache(): void;
    }

    /** Non-custodial wallet error */
    export class NonCustodialWalletError extends Error {
        name: 'NonCustodialWalletError';
        solution: string;
        timestamp: string;
        constructor(message: string, solution?: string);
    }

    /** Participant share for threshold signatures */
    export class ParticipantShare {
        readonly index: number;
        readonly keyShare: BNLike;
        readonly publicKeyShare: Buffer | null;

        constructor(index: number, keyShare: BNLike, publicKeyShare?: Buffer | null);

        toJSON(): ParticipantShareData;
        static fromJSON(json: ParticipantShareData): ParticipantShare;
    }

    /**
     * Non-custodial wallet with nChain Threshold Signature Scheme
     * 
     * Parameters:
     * - n: Total number of participants
     * - t: Threshold polynomial degree (t+1 to reconstruct, 2t+1 to sign)
     */
    export class NonCustodialWallet {
        readonly network: BitcoinNetwork;
        readonly n: number;
        readonly t: number;
        readonly signingThreshold: number;
        readonly reconstructionThreshold: number;
        readonly version: string;
        readonly created: number;

        constructor(network: BitcoinNetwork, n: number, t: number);

        /** Create new wallet with generated shares */
        static createNew(
            network?: BitcoinNetwork,
            n?: number,
            t?: number,
            ephemeralKeyCount?: number
        ): {
            wallet: NonCustodialWallet;
            shares: ParticipantShareData[];
            config: ThresholdConfig;
        };

        /** Restore wallet from existing shares (limited functionality) */
        static fromShares(
            network: BitcoinNetwork,
            shares: ParticipantShareData[],
            t: number
        ): NonCustodialWallet;

        /** Import wallet from exported data */
        static importShares(exportedData: {
            network: BitcoinNetwork;
            n: number;
            t: number;
            shares: ParticipantShareData[];
        }): NonCustodialWallet;

        /** Initialize the wallet with TSS key generation */
        initialize(ephemeralKeyCount?: number): void;

        /** Get wallet address */
        getAddress(type?: AddressType): string;

        /** Get all shares as JSON */
        getShares(): ParticipantShareData[];

        /** Get specific share by index */
        getShare(index: number): ParticipantShareData;

        /** Sign message hash with threshold participants */
        sign(messageHash: BufferLike, participantIndices?: number[]): ThresholdSignatureResult;

        /** Sign message with Bitcoin prefix */
        signMessage(message: string | Buffer, participantIndices?: number[]): ThresholdSignatureResult;

        /** Verify signature */
        verify(messageHash: BufferLike, signature: ThresholdSignatureResult | Buffer): boolean;

        /** Get aggregate public key */
        getPublicKey(): Buffer;

        /** Get threshold configuration */
        getThresholdConfig(): ThresholdConfig;

        /** Generate more ephemeral keys */
        generateEphemeralKeys(count?: number): void;

        /** Export wallet info */
        toJSON(): {
            network: BitcoinNetwork;
            version: string;
            created: number;
            n: number;
            t: number;
            signingThreshold: number;
            reconstructionThreshold: number;
            aggregatePublicKey: string | undefined;
            sharesCount: number;
        };

        /** Export shares for backup */
        exportShares(): {
            network: BitcoinNetwork;
            n: number;
            t: number;
            shares: ParticipantShareData[];
        };

        /** Clear sensitive data */
        clear(): void;
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // BIP IMPLEMENTATIONS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** BIP39 Mnemonic utilities */
    export class BIP39 {
        static generateMnemonic(strength?: 128 | 160 | 192 | 224 | 256): { mnemonic: string; entropy: Buffer };
        static validateChecksum(mnemonic: string): boolean;
        static deriveSeed(mnemonic: string, passphrase?: string): Buffer;
        static mnemonicToEntropy(mnemonic: string): Buffer;
        static entropyToMnemonic(entropy: BufferLike): string;
    }

    /** BIP173/BIP350 Bech32 encoding */
    export class BECH32 {
        static encode(hrp: string, data: number[]): string;
        static decode(address: string): { hrp: string; data: number[] };
        static to_P2WPKH(publicKey: string | Buffer, network?: BitcoinNetwork): string;
        static to_P2TR(xOnlyPubKey: Buffer, network?: BitcoinNetwork): string;
        static decodeAddress(address: string): { version: number; program: Buffer };
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // CRYPTOGRAPHY
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** ECDSA signature operations */
    export class ECDSA {
        static sign(privateKey: BufferLike, messageHash: BufferLike): ECDSASignature;
        static verify(signature: ECDSASignature, messageHash: BufferLike, publicKey: BufferLike): boolean;
        static signMessage(privateKey: string, message: string): ECDSASignature;
        static verifyMessage(signature: ECDSASignature, message: string, publicKey: string): boolean;
        static recoverPublicKey(signature: ECDSASignature, messageHash: BufferLike): Buffer;
    }

    /** Schnorr signature operations (BIP340) */
    export class Schnorr {
        static sign(privateKey: BufferLike, message: BufferLike): Buffer;
        static verify(signature: BufferLike, message: BufferLike, publicKey: BufferLike): boolean;
        static getPublicKey(privateKey: BufferLike): Buffer;
    }

    /** Alias for Schnorr */
    export const SchnorrSignature: typeof Schnorr;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // THRESHOLD SIGNATURES (nChain TSS Protocol)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** Polynomial for secret sharing */
    export class Polynomial {
        readonly coefficients: BNLike[];
        readonly degree: number;

        constructor(degree: number, secret?: BNLike | null);
        evaluate(x: number | BNLike): BNLike;
        getSecret(): BNLike;
        getCoefficients(): BNLike[];
        generateShares(n: number): InterpolationShare[];
        clear(): void;

        static lagrangeCoefficient(i: number, xCoords: BNLike[], x?: BNLike): BNLike;
        static interpolate(shares: InterpolationShare[], x?: BNLike): BNLike;
        static reconstructSecret(shares: InterpolationShare[]): BNLike;
    }

    /** Joint Verifiable Random Secret Sharing */
    export class JVRSS {
        readonly n: number;
        readonly t: number;
        readonly participants: any[];
        readonly sharedPublicKey: Buffer | null;

        constructor(n: number, t: number);

        getParticipant(index: number): any;
        generatePolynomials(): void;
        distributePolynomialPoints(): void;
        calculateShares(): void;
        broadcastObfuscatedCoefficients(): void;
        verifyAllShares(): { valid: boolean; invalidPairs: Array<{ verifier: number; sender: number }> };
        calculateSharedPublicKey(): Buffer;
        runProtocol(): {
            shares: Array<{ index: number; keyShare: BNLike; publicKeyShare: Buffer }>;
            publicKey: Buffer;
            verified: boolean;
        };
        getSharesForInterpolation(): InterpolationShare[];
        reconstructSecret(): BNLike;
        clear(): void;
    }

    /** Threshold Signature Scheme (nChain TSS Protocol) */
    export class ThresholdSignatureScheme {
        readonly n: number;
        readonly t: number;
        readonly signingThreshold: number;
        readonly reconstructionThreshold: number;

        constructor(n: number, t: number);

        /** Generate shared private key using JVRSS */
        generateSharedPrivateKey(): Buffer;

        /** Generate ephemeral keys for signing */
        generateEphemeralKeys(count?: number): void;

        /** Sign message hash with threshold participants */
        sign(messageHash: BufferLike, participantIndices?: number[]): ThresholdSignatureResult;

        /** Sign message with Bitcoin prefix */
        signMessage(message: string | Buffer, participantIndices?: number[]): ThresholdSignatureResult;

        /** Verify signature */
        verify(messageHash: BufferLike, signature: ThresholdSignatureResult | Buffer, publicKey?: Buffer): boolean;

        /** Get the shared public key */
        getPublicKey(): Buffer;

        /** Get configuration */
        getConfig(): ThresholdConfig;

        /** Clear sensitive data */
        clear(): void;
    }

    /** Create and initialize a threshold scheme */
    export function createThresholdScheme(
        n: number,
        t: number,
        ephemeralKeyCount?: number
    ): ThresholdSignatureScheme;

    /** Addition of shared secrets (Section 2.2) */
    export function ADDSS(
        aShares: InterpolationShare[],
        bShares: InterpolationShare[],
        threshold: number
    ): BNLike;

    /** Product of shared secrets (Section 2.3) */
    export function PROSS(
        aShares: InterpolationShare[],
        bShares: InterpolationShare[],
        productThreshold: number
    ): BNLike;

    /** Inverse of a shared secret (Section 2.4) */
    export function INVSS(
        aShares: InterpolationShare[],
        bShares: InterpolationShare[],
        t: number
    ): {
        mu: BNLike;
        muInverse: BNLike;
        inverseShares: InterpolationShare[];
    };

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // ENCODING FUNCTIONS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    export function b58encode(data: BufferLike): string;
    export function b58decode(encoded: string): Buffer;
    export function encodeP2PKH(publicKey: BufferLike, network?: BitcoinNetwork): string;
    export function encodeWIF(privateKey: BufferLike, network?: BitcoinNetwork): string;
    export function hash160(data: BufferLike): Buffer;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // KEY DERIVATION
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** Generate master key from seed (BIP32) */
    export function generateMasterKey(seed: BufferLike, network?: BitcoinNetwork): [HDKeys];

    /** Alias for generateMasterKey */
    export const fromSeed: typeof generateMasterKey;

    /** Derive child key from parent (BIP32) */
    export function derive(path: string, extendedKey: string): {
        privateKey: Buffer;
        publicKey: Buffer;
        chainCode: Buffer;
    };

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // CONSTANTS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /** Feature support matrix */
    export const FEATURES: Readonly<{
        HD_WALLETS: boolean;
        THRESHOLD_SIGNATURES: boolean;
        ECDSA: boolean;
        SCHNORR: boolean;
        P2PKH: boolean;
        P2WPKH: boolean;
        P2SH: boolean;
        P2WSH: boolean;
        P2TR: boolean;
        TRANSACTIONS: boolean;
        SPV: boolean;
        LIGHTNING: boolean;
    }>;

    /** Supported networks */
    export const NETWORKS: Readonly<{
        BTC_MAIN: NetworkConfig;
        BTC_TEST: NetworkConfig;
    }>;

    /** Library info */
    export const LIBRARY_INFO: Readonly<{
        name: string;
        version: string;
        description: string;
        author: string;
        license: string;
        repository: string;
    }>;

    /** BIP compliance */
    export const BIP_COMPLIANCE: Readonly<{
        BIP32: boolean;
        BIP39: boolean;
        BIP44: boolean;
        BIP49: boolean;
        BIP84: boolean;
        BIP86: boolean;
        BIP141: boolean;
        BIP143: boolean;
        BIP173: boolean;
        BIP340: boolean;
        BIP341: boolean;
        BIP342: boolean;
        BIP350: boolean;
    }>;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // DEFAULT EXPORT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    const JBitcoin: {
        CustodialWallet: typeof CustodialWallet;
        NonCustodialWallet: typeof NonCustodialWallet;
        ECDSA: typeof ECDSA;
        Schnorr: typeof Schnorr;
        SchnorrSignature: typeof Schnorr;
        Polynomial: typeof Polynomial;
        JVRSS: typeof JVRSS;
        ThresholdSignatureScheme: typeof ThresholdSignatureScheme;
        createThresholdScheme: typeof createThresholdScheme;
        ADDSS: typeof ADDSS;
        PROSS: typeof PROSS;
        INVSS: typeof INVSS;
        BIP39: typeof BIP39;
        BECH32: typeof BECH32;
        fromSeed: typeof generateMasterKey;
        derive: typeof derive;
        FEATURES: typeof FEATURES;
        NETWORKS: typeof NETWORKS;
        LIBRARY_INFO: typeof LIBRARY_INFO;
        BIP_COMPLIANCE: typeof BIP_COMPLIANCE;
    };

    export default JBitcoin;
}