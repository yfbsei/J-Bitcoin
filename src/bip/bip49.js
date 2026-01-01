/**
 * @fileoverview BIP49 - Wrapped SegWit Address Generation
 * @description P2SH-P2WPKH (3... addresses) derivation and address generation
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';
import rmd160 from '../core/crypto/hash/ripemd160.js';
import { encodeP2SH } from '../encoding/address/encode.js';
import { ScriptBuilder } from '../transaction/script-builder.js';

/**
 * Hash160 (SHA256 + RIPEMD160)
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} 20-byte hash
 */
function hash160(data) {
    const sha = createHash('sha256').update(data).digest();
    return rmd160(sha);
}

/**
 * BIP49 Derivation Path Constants
 * @constant {Object}
 */
const BIP49_CONSTANTS = {
    PURPOSE: 49,
    MAINNET_PATH: "m/49'/0'/0'",
    TESTNET_PATH: "m/49'/1'/0'"
};

/**
 * BIP49 utilities for wrapped SegWit addresses
 * @class BIP49
 */
class BIP49 {
    /**
     * Create P2SH-P2WPKH address from public key
     * @param {Buffer|string} publicKey - Compressed public key (33 bytes)
     * @param {string} [network='main'] - Network type
     * @returns {string} P2SH address (3... or 2...)
     */
    static toAddress(publicKey, network = 'main') {
        const pubKeyBuffer = Buffer.isBuffer(publicKey)
            ? publicKey
            : Buffer.from(publicKey, 'hex');

        if (pubKeyBuffer.length !== 33) {
            throw new Error('BIP49 requires 33-byte compressed public key');
        }

        // Create P2WPKH script: OP_0 <20-byte pubkey hash>
        const pubkeyHash = hash160(pubKeyBuffer);
        const p2wpkhScript = ScriptBuilder.createP2WPKH(pubkeyHash);

        // Hash the P2WPKH script to create P2SH script hash
        const scriptHash = hash160(p2wpkhScript);

        // Encode as P2SH address
        return encodeP2SH(scriptHash, network);
    }

    /**
     * Create redeem script for P2SH-P2WPKH
     * @param {Buffer|string} publicKey - Compressed public key
     * @returns {Buffer} Redeem script (P2WPKH script)
     */
    static createRedeemScript(publicKey) {
        const pubKeyBuffer = Buffer.isBuffer(publicKey)
            ? publicKey
            : Buffer.from(publicKey, 'hex');

        const pubkeyHash = hash160(pubKeyBuffer);
        return ScriptBuilder.createP2WPKH(pubkeyHash);
    }

    /**
     * Create scriptPubKey for P2SH-P2WPKH address
     * @param {Buffer|string} publicKey - Compressed public key
     * @returns {Buffer} P2SH scriptPubKey
     */
    static createScriptPubKey(publicKey) {
        const redeemScript = this.createRedeemScript(publicKey);
        const scriptHash = hash160(redeemScript);
        return ScriptBuilder.createP2SH(scriptHash);
    }

    /**
     * Get derivation path for BIP49
     * @param {string} [network='main'] - Network type
     * @param {number} [account=0] - Account index
     * @param {number} [change=0] - Change (0=external, 1=internal)
     * @param {number} [index=0] - Address index
     * @returns {string} Derivation path
     */
    static getDerivationPath(network = 'main', account = 0, change = 0, index = 0) {
        const coinType = network === 'main' ? 0 : 1;
        return `m/49'/${coinType}'/${account}'/${change}/${index}`;
    }

    /**
     * Get account-level derivation path
     * @param {string} [network='main'] - Network type
     * @param {number} [account=0] - Account index
     * @returns {string} Account path
     */
    static getAccountPath(network = 'main', account = 0) {
        const coinType = network === 'main' ? 0 : 1;
        return `m/49'/${coinType}'/${account}'`;
    }
}

export {
    BIP49,
    BIP49_CONSTANTS,
    hash160
};

export default BIP49;
