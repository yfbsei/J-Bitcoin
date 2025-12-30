/**
 * J-Bitcoin - TypeScript Definitions
 * @version 2.0.0
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
        r: bigint;
        s: bigint;
        participants: number;
        threshold: number;
    }

    /** Polynomial share for secret sharing */
    export interface PolynomialShareData {
        index: number;
        x: string;
        y: string;
        publicKey?: string | null;
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
        readonly x: any; // BN instance
        readonly y: any; // BN instance
        readonly publicKey: Buffer | null;

        constructor(index: number, x: any, y: any, publicKey?: any);

        toJSON(): PolynomialShareData;
        static fromJSON(json: PolynomialShareData): ParticipantShare;
    }

    /** Non-custodial wallet with threshold signatures */
    export class NonCustodialWallet {
        readonly network: BitcoinNetwork;
        readonly participants: number;
        readonly threshold: number;
        readonly version: string;
        readonly created: number;

        constructor(network: BitcoinNetwork, participants: number, threshold: number);

        /** Create new wallet with generated shares */
        static createNew(
            network?: BitcoinNetwork,
            participants?: number,
            threshold?: number
        ): { wallet: NonCustodialWallet; shares: PolynomialShareData[] };

        /** Restore wallet from existing shares */
        static fromShares(
            network: BitcoinNetwork,
            shares: PolynomialShareData[],
            threshold: number
        ): NonCustodialWallet;

        /** Import wallet from exported data */
        static importShares(exportedData: {
            network: BitcoinNetwork;
            threshold: number;
            participants: number;
            shares: PolynomialShareData[];
            commitments?: string[];
        }): NonCustodialWallet;

        /** Generate secret shares */
        generateShares(secret?: any): ParticipantShare[];

        /** Get wallet address */
        getAddress(type?: AddressType): string;

        /** Get all shares as JSON */
        getShares(): PolynomialShareData[];

        /** Get specific share by index */
        getShare(index: number): PolynomialShareData;

        /** Verify share is valid against commitments */
        verifyShare(share: PolynomialShareData): boolean;

        /** Sign message hash with threshold participants */
        signMessage(messageHash: BufferLike, participantIndices?: number[]): Promise<ThresholdSignatureResult>;

        /** Verify threshold signature */
        verifySignature(messageHash: BufferLike, signature: ThresholdSignatureResult): Promise<boolean>;

        /** Get aggregate public key */
        getPublicKey(): Buffer;

        /** Get threshold configuration */
        getThresholdConfig(): {
            threshold: number;
            participants: number;
            sharesAvailable: number;
        };

        /** Export wallet info */
        toJSON(): {
            network: BitcoinNetwork;
            version: string;
            created: number;
            threshold: number;
            participants: number;
            aggregatePublicKey: string | undefined;
            sharesCount: number;
        };

        /** Export shares for backup */
        exportShares(): {
            network: BitcoinNetwork;
            threshold: number;
            participants: number;
            shares: PolynomialShareData[];
            commitments?: string[];
        };
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

    /** Polynomial for secret sharing */
    export class Polynomial {
        readonly coefficients: any[]; // BN array
        readonly degree: number;

        constructor(coefficients: any[]);
        evaluate(x: any): any;
        static generateRandom(degree: number, constantTerm?: any): Polynomial;
        static reconstructSecret(shares: Array<{ x: any; y: any }>): any;
    }

    /** Threshold signature scheme */
    export class ThresholdSignature {
        readonly threshold: number;
        readonly participants: number;

        constructor(threshold: number, participants: number);
        generateShares(secret?: any): {
            shares: Array<{ index: number; x: any; y: any }>;
            commitments: Buffer[];
            publicKey: Buffer;
        };
        static generatePartialSignature(share: { y: any; index: number }, messageHash: BufferLike): any;
        static combinePartialSignatures(partialSigs: any[], threshold: number): ThresholdSignatureResult;
        static verifyThresholdSignature(publicKey: BufferLike, messageHash: BufferLike, signature: { r: bigint; s: bigint }): boolean;
    }

    /** Feldman VSS commitments */
    export class FeldmanCommitments {
        commitments: any[];
        constructor(polynomial: Polynomial);
        verifyShare(share: { x: any; y: any }): boolean;
    }

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
        ThresholdSignature: typeof ThresholdSignature;
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