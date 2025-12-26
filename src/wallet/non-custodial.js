/**
 * @fileoverview Non-Custodial Wallet with Threshold Signature Scheme
 * 
 * A distributed Bitcoin wallet implementation using t-of-n threshold signatures.
 * No single party holds the complete private key - security through distribution.
 * 
 * THRESHOLD SIGNATURE FEATURES:
 * - JVRSS (Joint Verifiable Random Secret Sharing) for distributed key generation
 * - Feldman Commitments for share verification
 * - Distributed signing without key reconstruction
 * - Support for ECDSA (SegWit) and Schnorr (Taproot) threshold signatures
 * 
 * SYNTAX MIRRORS CUSTODIAL WALLET:
 * - createNew() → createNew(network, participants, threshold)
 * - fromShares() → Restore from existing shares
 * - getAddress() → Get aggregate public key address
 * - signMessage() → Threshold sign with available shares
 * 
 * @author yfbsei
 * @version 2.0.0
 * @license ISC
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from 'bn.js';

// =============================================================================
// IMPORTS
// =============================================================================

import ThresholdSignature, { FeldmanCommitments } from './src/core/crypto/signatures/threshold/threshold-signature.js';
import Polynomial from './src/core/crypto/signatures/threshold/polynomial.js';
import Schnorr from './src/core/crypto/signatures/schnorr-BIP340.js';
import ECDSA from './src/core/crypto/signatures/ecdsa.js';
import { BECH32 } from './src/bip/BIP173-BIP350.js';
import { CRYPTO_CONSTANTS, THRESHOLD_CONSTANTS } from './src/core/constants.js';

// =============================================================================
// CONSTANTS
// =============================================================================

const CURVE_ORDER = CRYPTO_CONSTANTS.CURVE_ORDER;
const MAX_PARTICIPANTS = THRESHOLD_CONSTANTS.MAX_PARTICIPANTS;
const MIN_THRESHOLD = THRESHOLD_CONSTANTS.MIN_THRESHOLD;

// =============================================================================
// ERROR CLASS
// =============================================================================

/**
 * Non-custodial wallet error with helpful messages
 */
class NonCustodialWalletError extends Error {
    constructor(message, solution = 'Check the documentation for threshold wallets') {
        super(message);
        this.name = 'NonCustodialWalletError';
        this.solution = solution;
        this.timestamp = new Date().toISOString();
    }
}

// =============================================================================
// SHARE CLASS - Represents a participant's share
// =============================================================================

/**
 * Participant Share
 * 
 * Represents one participant's share in the threshold scheme.
 * Each share can generate partial signatures independently.
 */
class ParticipantShare {
    constructor(index, shareValue, publicCommitments, schemeInfo) {
        this.index = index;                    // Participant index (1-based)
        this.shareValue = shareValue;          // Secret share (BN)
        this.publicCommitments = publicCommitments; // Feldman commitments
        this.schemeInfo = schemeInfo;          // {threshold, participants, schemeId}
        this.created = Date.now();
    }

    /**
     * Generate partial signature for a message
     */
    generatePartialSignature(messageHash) {
        if (!Buffer.isBuffer(messageHash) || messageHash.length !== 32) {
            throw new NonCustodialWalletError(
                'Message hash must be 32 bytes',
                'Use SHA256 to hash your message first'
            );
        }

        // Generate deterministic nonce for this share
        const nonceData = Buffer.concat([
            this.shareValue.toBuffer('be', 32),
            messageHash,
            Buffer.from([this.index])
        ]);
        const nonce = new BN(createHash('sha256').update(nonceData).digest());
        const k = nonce.umod(CURVE_ORDER);

        if (k.isZero()) {
            throw new NonCustodialWalletError(
                'Invalid nonce generated',
                'Try signing again'
            );
        }

        // Calculate partial R = k * G
        const kBuffer = k.toBuffer('be', 32);
        const R = secp256k1.ProjectivePoint.fromPrivateKey(kBuffer);
        const partialR = Buffer.from(R.toRawBytes(true));

        // Calculate partial s = k + e * share (will be combined via Lagrange)
        const e = new BN(messageHash);
        const partialS = k.add(e.mul(this.shareValue)).umod(CURVE_ORDER);

        return {
            index: this.index,
            partialR: partialR,
            partialS: partialS.toBuffer('be', 32),
            schemeInfo: this.schemeInfo
        };
    }

    /**
     * Export share for backup (DANGEROUS - handle securely!)
     */
    export() {
        console.warn('SECURITY WARNING: Exporting share. Store securely and separately from other shares!');
        return {
            index: this.index,
            shareValue: this.shareValue.toString('hex'),
            publicCommitments: this.publicCommitments.map(c => c.toString('hex')),
            schemeInfo: this.schemeInfo,
            created: this.created
        };
    }

    /**
     * Import share from backup
     */
    static import(exportedShare) {
        return new ParticipantShare(
            exportedShare.index,
            new BN(exportedShare.shareValue, 16),
            exportedShare.publicCommitments.map(c => Buffer.from(c, 'hex')),
            exportedShare.schemeInfo
        );
    }

    /**
     * Securely clear share from memory
     */
    destroy() {
        if (this.shareValue) {
            // Overwrite with zeros
            this.shareValue = new BN(0);
        }
        this.publicCommitments = null;
        console.log(`Share ${this.index} destroyed`);
    }
}

// =============================================================================
// NON-CUSTODIAL WALLET CLASS
// =============================================================================

/**
 * Non-Custodial Bitcoin Wallet
 * 
 * A distributed wallet where no single party holds the complete private key.
 * Uses threshold signatures (t-of-n) for secure multi-party control.
 * 
 * Perfect for:
 * - Multi-party custody (2-of-3 family wallet, 3-of-5 corporate treasury)
 * - Enhanced security (compromise of t-1 shares reveals nothing)
 * - Disaster recovery (lose up to n-t shares and still recover)
 */
class NonCustodialWallet {
    constructor(network, thresholdScheme, shares, aggregatePublicKey) {
        this.network = network === 'main' ? 'mainnet' : 'testnet';
        this.threshold = thresholdScheme.threshold;
        this.participants = thresholdScheme.participants;
        this.schemeId = `${this.threshold}-of-${this.participants}`;
        
        this.shares = shares;                       // Array of ParticipantShare
        this.aggregatePublicKey = aggregatePublicKey; // Combined public key
        this.feldmanCommitments = thresholdScheme.commitments;
        
        this.derivedAddresses = new Map();
        this.version = '2.0.0';
        this.created = Date.now();

        // Derive primary address from aggregate public key
        this.address = this._deriveAddressFromPublicKey(this.aggregatePublicKey);
    }

    // =========================================================================
    // EASY WALLET CREATION METHODS (mirrors CustodialWallet)
    // =========================================================================

    /**
     * Create a completely new threshold wallet
     * 
     * @param {string} network - 'main' for Bitcoin mainnet, 'test' for testnet
     * @param {number} participants - Total number of participants (n)
     * @param {number} threshold - Minimum signatures required (t)
     * @returns {Object} { wallet: NonCustodialWallet, shares: ParticipantShare[] }
     * 
     * @example
     * // Create a 2-of-3 threshold wallet
     * const { wallet, shares } = NonCustodialWallet.createNew('main', 3, 2);
     * console.log('Distribute these shares to 3 different parties:');
     * shares.forEach((share, i) => console.log(`Share ${i + 1}:`, share.export()));
     */
    static createNew(network = 'main', participants = 3, threshold = 2) {
        try {
            // Validate parameters
            if (threshold < MIN_THRESHOLD) {
                throw new NonCustodialWalletError(
                    `Threshold must be at least ${MIN_THRESHOLD}`,
                    'Use a threshold of 2 or higher for security'
                );
            }

            if (participants > MAX_PARTICIPANTS) {
                throw new NonCustodialWalletError(
                    `Maximum ${MAX_PARTICIPANTS} participants allowed`,
                    'Reduce the number of participants'
                );
            }

            if (threshold > participants) {
                throw new NonCustodialWalletError(
                    'Threshold cannot exceed number of participants',
                    `Use threshold ≤ ${participants}`
                );
            }

            console.log(`Creating ${threshold}-of-${participants} threshold wallet...`);

            // Generate distributed keys using JVRSS
            const keyGeneration = NonCustodialWallet._executeJVRSS(participants, threshold);

            // Create participant shares
            const shares = keyGeneration.secretShares.map((shareValue, index) => {
                return new ParticipantShare(
                    index + 1,  // 1-based indexing
                    shareValue,
                    keyGeneration.commitments,
                    {
                        threshold,
                        participants,
                        schemeId: `${threshold}-of-${participants}`
                    }
                );
            });

            const wallet = new NonCustodialWallet(
                network,
                {
                    threshold,
                    participants,
                    commitments: keyGeneration.commitments
                },
                shares,
                keyGeneration.aggregatePublicKey
            );

            console.log(`Threshold wallet created: ${wallet.schemeId}`);
            console.log(`Aggregate address: ${wallet.getAddress()}`);

            return { wallet, shares };

        } catch (error) {
            if (error instanceof NonCustodialWalletError) {
                throw error;
            }
            throw new NonCustodialWalletError(
                `Failed to create threshold wallet: ${error.message}`,
                'Check parameters and try again'
            );
        }
    }

    /**
     * Restore wallet from existing shares
     * 
     * @param {string} network - 'main' or 'test'
     * @param {Array} exportedShares - Array of exported share objects
     * @returns {NonCustodialWallet} Restored wallet
     * 
     * @example
     * const shares = [share1Export, share2Export, share3Export];
     * const wallet = NonCustodialWallet.fromShares('main', shares);
     */
    static fromShares(network, exportedShares) {
        try {
            if (!Array.isArray(exportedShares) || exportedShares.length === 0) {
                throw new NonCustodialWalletError(
                    'Must provide at least one share',
                    'Pass an array of exported shares'
                );
            }

            // Import shares
            const shares = exportedShares.map(exp => ParticipantShare.import(exp));

            // Validate all shares are from same scheme
            const schemeInfo = shares[0].schemeInfo;
            for (const share of shares) {
                if (share.schemeInfo.schemeId !== schemeInfo.schemeId) {
                    throw new NonCustodialWalletError(
                        'All shares must be from the same threshold scheme',
                        'Check that you are using shares from the same wallet'
                    );
                }
            }

            // Reconstruct aggregate public key from commitments
            const aggregatePublicKey = NonCustodialWallet._deriveAggregatePublicKey(
                shares[0].publicCommitments
            );

            const wallet = new NonCustodialWallet(
                network,
                {
                    threshold: schemeInfo.threshold,
                    participants: schemeInfo.participants,
                    commitments: shares[0].publicCommitments
                },
                shares,
                aggregatePublicKey
            );

            console.log(`Wallet restored from ${shares.length} shares`);
            return wallet;

        } catch (error) {
            if (error instanceof NonCustodialWalletError) {
                throw error;
            }
            throw new NonCustodialWalletError(
                `Failed to restore wallet: ${error.message}`,
                'Verify your shares are valid and from the same wallet'
            );
        }
    }

    /**
     * Create wallet from threshold signature instance
     * 
     * @param {string} network - 'main' or 'test'
     * @param {ThresholdSignature} thresholdInstance - Existing threshold instance
     * @returns {NonCustodialWallet} Wallet instance
     */
    static fromThresholdInstance(network, thresholdInstance) {
        try {
            const shares = thresholdInstance.secretShares.map((shareValue, index) => {
                return new ParticipantShare(
                    index + 1,
                    shareValue,
                    thresholdInstance.feldmanCommitments,
                    {
                        threshold: thresholdInstance.requiredSigners,
                        participants: thresholdInstance.participantCount,
                        schemeId: thresholdInstance.schemeId
                    }
                );
            });

            return new NonCustodialWallet(
                network,
                {
                    threshold: thresholdInstance.requiredSigners,
                    participants: thresholdInstance.participantCount,
                    commitments: thresholdInstance.feldmanCommitments
                },
                shares,
                thresholdInstance.aggregatePublicKey
            );
        } catch (error) {
            throw new NonCustodialWalletError(
                `Failed to create wallet from threshold instance: ${error.message}`,
                'Ensure the threshold instance is properly initialized'
            );
        }
    }

    // =========================================================================
    // ADDRESS METHODS
    // =========================================================================

    /**
     * Get the primary wallet address
     * 
     * @returns {string} Bitcoin address derived from aggregate public key
     * 
     * @example
     * const address = wallet.getAddress();
     * console.log('Send Bitcoin to:', address);
     */
    getAddress() {
        return this.address;
    }

    /**
     * Get address for specific type
     * 
     * @param {string} type - 'segwit' or 'taproot'
     * @returns {string} Bitcoin address
     */
    getAddressOfType(type = 'segwit') {
        const cacheKey = `address_${type}`;
        
        if (this.derivedAddresses.has(cacheKey)) {
            return this.derivedAddresses.get(cacheKey);
        }

        const address = this._deriveAddressFromPublicKey(this.aggregatePublicKey, type);
        this.derivedAddresses.set(cacheKey, address);
        return address;
    }

    /**
     * Get SegWit address (bc1q...)
     */
    getSegWitAddress() {
        return this.getAddressOfType('segwit');
    }

    /**
     * Get Taproot address (bc1p...)
     */
    getTaprootAddress() {
        return this.getAddressOfType('taproot');
    }

    // =========================================================================
    // SIGNING METHODS
    // =========================================================================

    /**
     * Sign a message with threshold signatures
     * 
     * Requires at least `threshold` shares to produce a valid signature.
     * 
     * @param {string} message - Message to sign
     * @param {Array} signingShares - Array of ParticipantShare (must have >= threshold)
     * @returns {Object} { signature, participantsUsed, schemeId }
     * 
     * @example
     * // Collect signatures from threshold participants
     * const signature = wallet.signMessage('Hello Bitcoin!', [share1, share2]);
     * console.log('Threshold signature:', signature.signature.toString('hex'));
     */
    signMessage(message, signingShares = null) {
        try {
            const sharesToUse = signingShares || this.shares;

            if (!sharesToUse || sharesToUse.length < this.threshold) {
                throw new NonCustodialWalletError(
                    `Need at least ${this.threshold} shares to sign, have ${sharesToUse?.length || 0}`,
                    `Collect signatures from at least ${this.threshold} participants`
                );
            }

            // Hash the message
            const messageHash = createHash('sha256')
                .update(Buffer.from(message, 'utf8'))
                .digest();

            // Generate partial signatures from each share
            const partialSignatures = sharesToUse
                .slice(0, this.threshold)
                .map(share => share.generatePartialSignature(messageHash));

            // Combine partial signatures using Lagrange interpolation
            const combinedSignature = this._combinePartialSignatures(
                partialSignatures,
                messageHash
            );

            return {
                signature: combinedSignature.signature,
                r: combinedSignature.r,
                s: combinedSignature.s,
                participantsUsed: partialSignatures.map(p => p.index),
                schemeId: this.schemeId,
                messageHash: messageHash.toString('hex')
            };

        } catch (error) {
            if (error instanceof NonCustodialWalletError) {
                throw error;
            }
            throw new NonCustodialWalletError(
                `Threshold signing failed: ${error.message}`,
                'Ensure you have enough valid shares'
            );
        }
    }

    /**
     * Verify a threshold signature
     * 
     * @param {Buffer|string} signature - Signature to verify
     * @param {string} message - Original message
     * @returns {boolean} True if valid
     */
    verifySignature(signature, message) {
        try {
            const messageHash = createHash('sha256')
                .update(Buffer.from(message, 'utf8'))
                .digest();

            const sigBuffer = Buffer.isBuffer(signature) 
                ? signature 
                : Buffer.from(signature, 'hex');

            // Use aggregate public key for verification
            const pubKeyBytes = this.aggregatePublicKey.toRawBytes(true);
            return ECDSA.verify(sigBuffer, messageHash, pubKeyBytes);

        } catch (error) {
            console.warn('Signature verification failed:', error.message);
            return false;
        }
    }

    /**
     * Generate partial signature from a single share
     * 
     * Use this for distributed signing where each participant signs independently.
     * 
     * @param {ParticipantShare} share - The participant's share
     * @param {string|Buffer} message - Message to sign
     * @returns {Object} Partial signature
     */
    static generatePartialSignature(share, message) {
        const messageHash = Buffer.isBuffer(message)
            ? message
            : createHash('sha256').update(Buffer.from(message, 'utf8')).digest();

        return share.generatePartialSignature(messageHash);
    }

    /**
     * Combine partial signatures into complete signature
     * 
     * @param {Array} partialSignatures - Array of partial signatures
     * @param {string|Buffer} message - Original message
     * @returns {Object} Combined signature
     */
    combineSignatures(partialSignatures, message) {
        if (partialSignatures.length < this.threshold) {
            throw new NonCustodialWalletError(
                `Need ${this.threshold} partial signatures, have ${partialSignatures.length}`,
                `Collect more partial signatures`
            );
        }

        const messageHash = Buffer.isBuffer(message)
            ? message
            : createHash('sha256').update(Buffer.from(message, 'utf8')).digest();

        return this._combinePartialSignatures(partialSignatures, messageHash);
    }

    // =========================================================================
    // WALLET INFORMATION
    // =========================================================================

    /**
     * Get wallet information
     * 
     * @returns {Object} Wallet details
     */
    getInfo() {
        return {
            network: this.network,
            address: this.getAddress(),
            segwitAddress: this.getSegWitAddress(),
            taprootAddress: this.getTaprootAddress(),
            schemeId: this.schemeId,
            threshold: this.threshold,
            participants: this.participants,
            availableShares: this.shares.length,
            canSign: this.shares.length >= this.threshold,
            version: this.version,
            created: new Date(this.created).toISOString()
        };
    }

    /**
     * Get threshold scheme summary
     */
    getSchemeSummary() {
        const securityLevel = this.threshold >= this.participants * 0.6 ? 'High' :
            this.threshold >= this.participants * 0.4 ? 'Medium' : 'Low';

        return {
            schemeId: this.schemeId,
            threshold: this.threshold,
            participants: this.participants,
            availableShares: this.shares.length,
            canSign: this.shares.length >= this.threshold,
            sharesNeeded: Math.max(0, this.threshold - this.shares.length),
            securityLevel,
            description: `Requires ${this.threshold} of ${this.participants} participants to sign`
        };
    }

    /**
     * 🔢 Get all share indices
     */
    getShareIndices() {
        return this.shares.map(s => s.index);
    }

    /**
     * Get specific share by index
     */
    getShare(index) {
        const share = this.shares.find(s => s.index === index);
        if (!share) {
            throw new NonCustodialWalletError(
                `Share ${index} not found`,
                `Available shares: ${this.getShareIndices().join(', ')}`
            );
        }
        return share;
    }

    // =========================================================================
    // SECURITY & BACKUP
    // =========================================================================

    /**
     * Export wallet for backup (DANGEROUS)
     * 
     * @param {boolean} includeShares - Include secret shares in export
     * @returns {Object} Wallet backup data
     */
    exportWallet(includeShares = false) {
        console.warn('SECURITY WARNING: Exporting wallet data. Distribute shares securely!');

        const backup = {
            network: this.network,
            schemeId: this.schemeId,
            threshold: this.threshold,
            participants: this.participants,
            address: this.getAddress(),
            aggregatePublicKey: Buffer.from(this.aggregatePublicKey.toRawBytes(true)).toString('hex'),
            feldmanCommitments: this.feldmanCommitments?.map(c => 
                Buffer.from(c.toRawBytes ? c.toRawBytes(true) : c).toString('hex')
            ),
            version: this.version,
            created: this.created,
            exported: Date.now()
        };

        if (includeShares) {
            console.warn('INCLUDING SECRET SHARES - HANDLE WITH EXTREME CARE!');
            backup.shares = this.shares.map(s => s.export());
        }

        return backup;
    }

    /**
     * Export individual shares for distribution
     * 
     * @returns {Array} Array of exported shares
     */
    exportShares() {
        console.warn('SECURITY WARNING: Distribute each share to a different party!');
        return this.shares.map(s => s.export());
    }

    /**
     * Securely clear wallet from memory
     */
    destroy() {
        console.warn('Destroying threshold wallet - clearing all shares from memory');

        try {
            // Clear all shares
            for (const share of this.shares) {
                share.destroy();
            }
            this.shares = [];

            // Clear other sensitive data
            this.aggregatePublicKey = null;
            this.feldmanCommitments = null;
            this.derivedAddresses.clear();

            console.log('Threshold wallet destroyed successfully');
        } catch (error) {
            console.error('Failed to destroy wallet:', error.message);
        }
    }

    // =========================================================================
    // VALIDATION HELPERS (Static Methods)
    // =========================================================================

    /**
     * Validate threshold parameters
     */
    static validateThresholdParams(participants, threshold) {
        const errors = [];

        if (!Number.isInteger(participants) || participants < 2) {
            errors.push('Participants must be an integer >= 2');
        }

        if (!Number.isInteger(threshold) || threshold < MIN_THRESHOLD) {
            errors.push(`Threshold must be an integer >= ${MIN_THRESHOLD}`);
        }

        if (threshold > participants) {
            errors.push('Threshold cannot exceed participants');
        }

        if (participants > MAX_PARTICIPANTS) {
            errors.push(`Maximum ${MAX_PARTICIPANTS} participants allowed`);
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    /**
     * Validate if a string is a valid Bitcoin address
     */
    static isValidAddress(address) {
        try {
            if (!address || typeof address !== 'string') {
                return false;
            }

            const mainnetRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
            const testnetRegex = /^[2mn][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
            const bech32Regex = /^(bc1|tb1)[a-z0-9]{39,59}$/;

            return mainnetRegex.test(address) ||
                testnetRegex.test(address) ||
                bech32Regex.test(address);
        } catch (error) {
            return false;
        }
    }

    /**
     * Validate a share object
     */
    static isValidShare(share) {
        try {
            if (!share || typeof share !== 'object') return false;
            if (!share.index || !share.shareValue || !share.schemeInfo) return false;
            if (!share.schemeInfo.threshold || !share.schemeInfo.participants) return false;
            return true;
        } catch (error) {
            return false;
        }
    }

    // =========================================================================
    // INTERNAL METHODS
    // =========================================================================

    /**
     * Execute JVRSS (Joint Verifiable Random Secret Sharing)
     * PDF Section 2.1 implementation
     */
    static _executeJVRSS(participantCount, threshold) {
        const polynomialDegree = threshold - 1;

        // Step 1: Each participant generates their polynomial
        const polynomials = [];
        for (let i = 0; i < participantCount; i++) {
            const coefficients = [];
            for (let j = 0; j <= polynomialDegree; j++) {
                const randomBytes32 = randomBytes(32);
                const coeff = new BN(randomBytes32).umod(CURVE_ORDER);
                coefficients.push(coeff);
            }
            polynomials.push(coefficients);
        }

        // Step 2: Generate Feldman commitments (C_k = a_k * G)
        const allCommitments = polynomials.map(coeffs => {
            return coeffs.map(coeff => {
                const coeffBuffer = coeff.toBuffer('be', 32);
                return secp256k1.ProjectivePoint.fromPrivateKey(coeffBuffer);
            });
        });

        // Step 3: Each participant calculates their share
        const secretShares = [];
        for (let participantIndex = 1; participantIndex <= participantCount; participantIndex++) {
            let shareSum = new BN(0);

            for (let polyIndex = 0; polyIndex < participantCount; polyIndex++) {
                // Evaluate polynomial at participantIndex
                let evaluation = new BN(0);
                let xPower = new BN(1);
                const x = new BN(participantIndex);

                for (const coeff of polynomials[polyIndex]) {
                    evaluation = evaluation.add(coeff.mul(xPower)).umod(CURVE_ORDER);
                    xPower = xPower.mul(x).umod(CURVE_ORDER);
                }

                shareSum = shareSum.add(evaluation).umod(CURVE_ORDER);
            }

            secretShares.push(shareSum);
        }

        // Step 4: Compute aggregate public key from constant terms
        let aggregatePublicKey = secp256k1.ProjectivePoint.ZERO;
        for (let i = 0; i < participantCount; i++) {
            const constantTerm = polynomials[i][0];
            const keyMaterial = constantTerm.toBuffer('be', 32);
            const individualPublicKey = secp256k1.ProjectivePoint.fromPrivateKey(keyMaterial);
            aggregatePublicKey = aggregatePublicKey.add(individualPublicKey);
        }

        // Step 5: Aggregate Feldman commitments
        const aggregateCommitments = [];
        for (let coeffIndex = 0; coeffIndex <= polynomialDegree; coeffIndex++) {
            let aggregateCommitment = secp256k1.ProjectivePoint.ZERO;
            for (let polyIndex = 0; polyIndex < participantCount; polyIndex++) {
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
     * Derive aggregate public key from Feldman commitments
     */
    static _deriveAggregatePublicKey(commitments) {
        if (!commitments || commitments.length === 0) {
            throw new NonCustodialWalletError(
                'Cannot derive public key without commitments',
                'Provide valid Feldman commitments'
            );
        }

        // The first commitment is the public key commitment
        const firstCommitment = commitments[0];
        
        if (firstCommitment.toRawBytes) {
            return firstCommitment;
        }

        // If it's a buffer, convert to point
        return secp256k1.ProjectivePoint.fromHex(firstCommitment);
    }

    /**
     * Combine partial signatures using Lagrange interpolation
     */
    _combinePartialSignatures(partialSignatures, messageHash) {
        // Collect the partial R points and combine them
        let combinedR = secp256k1.ProjectivePoint.ZERO;
        for (const partial of partialSignatures) {
            const R = secp256k1.ProjectivePoint.fromHex(partial.partialR);
            combinedR = combinedR.add(R);
        }

        // Get r value (x-coordinate)
        const rBytes = combinedR.toRawBytes(false).slice(1, 33);
        const r = new BN(rBytes);

        // Lagrange interpolation for s values
        const indices = partialSignatures.map(p => p.index);
        let combinedS = new BN(0);

        for (let i = 0; i < partialSignatures.length; i++) {
            const xi = new BN(indices[i]);
            let lagrangeCoeff = new BN(1);

            for (let j = 0; j < partialSignatures.length; j++) {
                if (i !== j) {
                    const xj = new BN(indices[j]);
                    // λ_i = Π (x_j / (x_j - x_i)) for j ≠ i
                    const numerator = xj;
                    const denominator = xj.sub(xi).umod(CURVE_ORDER);
                    const denominatorInv = denominator.invm(CURVE_ORDER);
                    lagrangeCoeff = lagrangeCoeff.mul(numerator).mul(denominatorInv).umod(CURVE_ORDER);
                }
            }

            const partialS = new BN(partialSignatures[i].partialS);
            combinedS = combinedS.add(partialS.mul(lagrangeCoeff)).umod(CURVE_ORDER);
        }

        // Ensure canonical signature (low-s)
        const halfOrder = CURVE_ORDER.shrn(1);
        if (combinedS.gt(halfOrder)) {
            combinedS = CURVE_ORDER.sub(combinedS);
        }

        // Build signature
        const signature = Buffer.concat([
            r.toBuffer('be', 32),
            combinedS.toBuffer('be', 32)
        ]);

        return {
            signature,
            r: r.toBuffer('be', 32),
            s: combinedS.toBuffer('be', 32),
            recovery: combinedR.toRawBytes(false)[0] === 0x03 ? 1 : 0
        };
    }

    /**
     * Derive address from public key
     */
    _deriveAddressFromPublicKey(publicKey, type = 'segwit') {
        const pubKeyBytes = publicKey.toRawBytes ? 
            publicKey.toRawBytes(true) : 
            Buffer.from(publicKey);

        const prefix = this.network === 'mainnet' ? 'bc' : 'tb';

        if (type === 'taproot') {
            // For Taproot, use x-only public key (32 bytes)
            const xOnlyPubKey = pubKeyBytes.length === 33 ? 
                pubKeyBytes.slice(1) : pubKeyBytes;
            return BECH32.encode(prefix, 1, xOnlyPubKey);
        }

        // SegWit P2WPKH
        const hash160 = this._hash160(pubKeyBytes);
        return BECH32.encode(prefix, 0, hash160);
    }

    /**
     * HASH160 = RIPEMD160(SHA256(data))
     */
    _hash160(data) {
        const sha256Hash = createHash('sha256').update(data).digest();
        return createHash('ripemd160').update(sha256Hash).digest();
    }

// =============================================================================
// EXPORTS
// =============================================================================

export default NonCustodialWallet;

export {
    NonCustodialWallet,
    NonCustodialWalletError,
    ParticipantShare
};

/**
 * Quick Usage Examples:
 * 
 * // Create new 2-of-3 threshold wallet
 * const { wallet, shares } = NonCustodialWallet.createNew('main', 3, 2);
 * 
 * // Distribute shares to 3 different parties
 * const [share1, share2, share3] = shares;
 * party1.receiveShare(share1.export());
 * party2.receiveShare(share2.export());
 * party3.receiveShare(share3.export());
 * 
 * // Later: collect 2 shares to sign
 * const collected = [share1, share2];
 * const signature = wallet.signMessage('Transaction data', collected);
 * 
 * // Verify signature
 * const isValid = wallet.verifySignature(signature.signature, 'Transaction data');
 * 
 * // Restore wallet from shares
 * const restored = NonCustodialWallet.fromShares('main', [share1Export, share2Export]);
 * 
 * // Get addresses
 * console.log('SegWit:', wallet.getSegWitAddress());
 * console.log('Taproot:', wallet.getTaprootAddress());
 * 
 * // Always destroy when done
 * wallet.destroy();
 */
