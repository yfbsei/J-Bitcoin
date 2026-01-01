/**
 * @fileoverview Non-Custodial Wallet BTC Standards Compliance Tests
 * @description Tests the NonCustodialWallet against Bitcoin standards (BIP32/39/44/49/84/86 + TSS)
 * @version 1.0.0
 * 
 * Run: node src/wallet/non-custodial-test.js
 */

import { NonCustodialWallet } from '../src/wallet/non-custodial.js';
import { createHash } from 'node:crypto';

// Test vectors from BIP39/BIP32 standards
const TEST_VECTORS = {
    // Standard test mnemonic (DO NOT USE IN PRODUCTION)
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',

    // Expected addresses for different BIP standards (account 0, index 0)
    expectedAddresses: {
        // BIP44 (Legacy P2PKH) - m/44'/0'/0'/0/0
        legacy: {
            mainnet: '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA'
        },
        // BIP49 (Wrapped SegWit P2SH-P2WPKH) - m/49'/0'/0'/0/0
        'wrapped-segwit': {
            mainnet: '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf'
        },
        // BIP84 (Native SegWit P2WPKH) - m/84'/0'/0'/0/0
        segwit: {
            mainnet: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'
        },
        // BIP86 (Taproot P2TR) - m/86'/0'/0'/0/0
        taproot: {
            mainnet: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'
        }
    }
};

class TestRunner {
    constructor() {
        this.passed = 0;
        this.failed = 0;
    }

    assert(condition, testName, details = '') {
        if (condition) {
            this.passed++;
            console.log(`  ✓ ${testName}`);
        } else {
            this.failed++;
            console.log(`  ✗ ${testName}`);
            if (details) console.log(`    ${details}`);
        }
    }

    section(name) {
        console.log(`\n=== ${name} ===`);
    }

    summary() {
        console.log(`\n${'='.repeat(50)}`);
        console.log(`Total: ${this.passed + this.failed} | Passed: ${this.passed} | Failed: ${this.failed}`);
        console.log('='.repeat(50));
        return this.failed === 0;
    }
}

async function runTests() {
    const t = new TestRunner();
    console.log('Non-Custodial Wallet BTC Standards Compliance Tests');
    console.log('='.repeat(50));

    // ============================================
    // TSS (Threshold Signature Scheme) Tests
    // ============================================
    t.section('TSS Key Generation');

    try {
        const { wallet, shares, config } = NonCustodialWallet.createNew('main', 3, 1);

        t.assert(wallet !== null, 'TSS wallet created');
        t.assert(shares.length === 3, 'Generated 3 shares for n=3');
        t.assert(config.signingThreshold === 3, 'Signing threshold is 2t+1 = 3');
        t.assert(config.reconstructionThreshold === 2, 'Reconstruction threshold is t+1 = 2');

        const pubKey = wallet.getPublicKey();
        t.assert(pubKey !== null, 'Aggregate public key generated');
        t.assert(pubKey.length === 33, 'Compressed public key is 33 bytes');
    } catch (e) {
        t.assert(false, 'TSS key generation', e.message);
    }

    // ============================================
    // TSS Signing Tests
    // ============================================
    t.section('TSS Threshold Signing');

    try {
        const { wallet } = NonCustodialWallet.createNew('main', 3, 1);

        // Sign a message hash
        const messageHash = createHash('sha256').update('test message').digest();
        const signature = wallet.sign(messageHash);

        t.assert(signature !== null, 'Threshold signature created');
        t.assert(signature.r && signature.r.length === 64, 'Signature r component is 64 hex chars');
        t.assert(signature.s && signature.s.length === 64, 'Signature s component is 64 hex chars');

        // Verify signature
        const verified = wallet.verify(messageHash, signature);
        t.assert(verified === true, 'Threshold signature verified');

        // Test message signing with Bitcoin prefix
        const msgSig = wallet.signMessage('Hello Bitcoin');
        t.assert(msgSig !== null, 'Bitcoin message signature created');
    } catch (e) {
        t.assert(false, 'TSS signing', e.message);
    }

    // ============================================
    // HD Wallet Creation Tests
    // ============================================
    t.section('HD Wallet Creation (createNewHD)');

    try {
        const { wallet, mnemonic, shares } = NonCustodialWallet.createNewHD('main', 3, 1);

        t.assert(wallet.hasHD() === true, 'HD wallet has HD enabled');
        t.assert(mnemonic.split(' ').length >= 12, 'Mnemonic has at least 12 words');
        t.assert(shares.length === 3, 'TSS shares still generated');

        const xpub = wallet.getExtendedPublicKey();
        t.assert(xpub && xpub.startsWith('xpub'), 'Extended public key starts with xpub');

        const xprv = wallet.getExtendedPrivateKey();
        t.assert(xprv && xprv.startsWith('xprv'), 'Extended private key starts with xprv');
    } catch (e) {
        t.assert(false, 'HD wallet creation', e.message);
    }

    // ============================================
    // BIP39 Mnemonic Restoration Tests
    // ============================================
    t.section('BIP39 Mnemonic Restoration');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);

        t.assert(wallet !== null, 'Wallet restored from mnemonic');
        t.assert(wallet.hasHD() === true, 'Restored wallet has HD');
        t.assert(wallet.getMnemonic() === TEST_VECTORS.mnemonic, 'Mnemonic stored correctly');
    } catch (e) {
        t.assert(false, 'Mnemonic restoration', e.message);
    }

    // ============================================
    // BIP44 Legacy Address Tests
    // ============================================
    t.section('BIP44 Legacy Addresses (P2PKH)');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);
        const addr = wallet.getReceivingAddress(0, 0, 'legacy');

        t.assert(addr.address.startsWith('1'), 'P2PKH address starts with 1');
        t.assert(addr.path === "m/44'/0'/0'/0/0", 'Correct BIP44 path');

        const expected = TEST_VECTORS.expectedAddresses.legacy.mainnet;
        t.assert(addr.address === expected, 'Address matches BIP44 test vector',
            `Expected: ${expected}, Got: ${addr.address}`);
    } catch (e) {
        t.assert(false, 'BIP44 tests', e.message);
    }

    // ============================================
    // BIP49 Wrapped SegWit Tests
    // ============================================
    t.section('BIP49 Wrapped SegWit (P2SH-P2WPKH)');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);
        const addr = wallet.getReceivingAddress(0, 0, 'wrapped-segwit');

        t.assert(addr.address.startsWith('3'), 'P2SH address starts with 3');
        t.assert(addr.path === "m/49'/0'/0'/0/0", 'Correct BIP49 path');
        t.assert(addr.redeemScript !== null, 'Redeem script present');

        const expected = TEST_VECTORS.expectedAddresses['wrapped-segwit'].mainnet;
        t.assert(addr.address === expected, 'Address matches BIP49 test vector',
            `Expected: ${expected}, Got: ${addr.address}`);
    } catch (e) {
        t.assert(false, 'BIP49 tests', e.message);
    }

    // ============================================
    // BIP84 Native SegWit Tests
    // ============================================
    t.section('BIP84 Native SegWit (P2WPKH)');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);
        const addr = wallet.getReceivingAddress(0, 0, 'segwit');

        t.assert(addr.address.startsWith('bc1q'), 'P2WPKH address starts with bc1q');
        t.assert(addr.path === "m/84'/0'/0'/0/0", 'Correct BIP84 path');

        const expected = TEST_VECTORS.expectedAddresses.segwit.mainnet;
        t.assert(addr.address === expected, 'Address matches BIP84 test vector',
            `Expected: ${expected}, Got: ${addr.address}`);
    } catch (e) {
        t.assert(false, 'BIP84 tests', e.message);
    }

    // ============================================
    // BIP86 Taproot Tests
    // ============================================
    t.section('BIP86 Taproot (P2TR)');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);
        const addr = wallet.getReceivingAddress(0, 0, 'taproot');

        t.assert(addr.address.startsWith('bc1p'), 'P2TR address starts with bc1p');
        t.assert(addr.path === "m/86'/0'/0'/0/0", 'Correct BIP86 path');
        t.assert(addr.address.length === 62, 'Taproot address is 62 characters');
    } catch (e) {
        t.assert(false, 'BIP86 tests', e.message);
    }

    // ============================================
    // Multiple Address Generation Tests
    // ============================================
    t.section('Multiple Address Generation');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);

        const addresses = wallet.getAddresses(0, 'segwit', 20);
        t.assert(addresses.length === 20, 'Generated 20 addresses');

        const unique = new Set(addresses.map(a => a.address));
        t.assert(unique.size === 20, 'All addresses are unique');

        // Receiving vs change
        const receive = wallet.getReceivingAddress(0, 0, 'segwit');
        const change = wallet.getChangeAddress(0, 0, 'segwit');
        t.assert(receive.address !== change.address, 'Receiving and change differ');
    } catch (e) {
        t.assert(false, 'Multiple address tests', e.message);
    }

    // ============================================
    // fromExtendedKey Tests
    // ============================================
    t.section('Import from Extended Key');

    try {
        const { wallet } = NonCustodialWallet.createNewHD('main', 3, 1);
        const xprv = wallet.getExtendedPrivateKey();

        const imported = NonCustodialWallet.fromExtendedKey('main', xprv, 3, 1);
        t.assert(imported.hasHD() === true, 'Imported wallet has HD');
        t.assert(imported.getExtendedPrivateKey() === xprv, 'xprv preserved');

        // Addresses should match
        const origAddr = wallet.getReceivingAddress(0, 0, 'segwit');
        const importAddr = imported.getReceivingAddress(0, 0, 'segwit');
        t.assert(origAddr.address === importAddr.address, 'Addresses match after import');
    } catch (e) {
        t.assert(false, 'fromExtendedKey tests', e.message);
    }

    // ============================================
    // WIF Export/Import Tests
    // ============================================
    t.section('WIF Export');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);

        const wif = wallet.exportWIF(0, 0, 0, 'segwit');
        t.assert(wif !== null, 'WIF export successful');
        t.assert(wif.startsWith('K') || wif.startsWith('L'), 'Compressed WIF prefix');
        t.assert(wif.length === 52, 'WIF is 52 characters');
    } catch (e) {
        t.assert(false, 'WIF export tests', e.message);
    }

    // ============================================
    // HD Message Signing Tests
    // ============================================
    t.section('HD Message Signing');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);
        const message = 'Hello Bitcoin!';

        const sig = wallet.signMessageHD(message, 0, 0, 'segwit');
        t.assert(sig !== null, 'HD message signature created');
        t.assert(sig.signature !== undefined, 'Signature has signature property');

        // Verify signature - pass sig.signature not the whole object
        const addr = wallet.getReceivingAddress(0, 0, 'segwit');
        const verified = wallet.verifyMessageHD(message, sig.signature, addr.publicKeyBuffer);
        t.assert(verified === true, 'HD message signature verified');
    } catch (e) {
        t.assert(false, 'HD message signing', e.message);
    }

    // ============================================
    // Transaction Builder Tests
    // ============================================
    t.section('Transaction Support');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);

        const txBuilder = wallet.createTransaction();
        t.assert(txBuilder !== null, 'TransactionBuilder created');
        t.assert(typeof txBuilder.addInput === 'function', 'TransactionBuilder has addInput');
        t.assert(typeof txBuilder.addOutput === 'function', 'TransactionBuilder has addOutput');
    } catch (e) {
        t.assert(false, 'Transaction builder', e.message);
    }

    // ============================================
    // Utility Method Tests
    // ============================================
    t.section('Utility Methods');

    try {
        const wallet = NonCustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic, 3, 1);

        t.assert(wallet.getNetwork() === 'main', 'getNetwork() returns main');
        t.assert(wallet.canSign() === true, 'canSign() returns true');
        t.assert(wallet.canSignHD() === true, 'canSignHD() returns true');
        t.assert(wallet.hasHD() === true, 'hasHD() returns true');

        const json = wallet.toJSON();
        t.assert(json.hasHD === true, 'toJSON() includes hasHD');
        t.assert(json.extendedPublicKey !== null, 'toJSON() includes xpub');
    } catch (e) {
        t.assert(false, 'Utility methods', e.message);
    }

    // ============================================
    // Dual Mode: TSS + HD Coexistence
    // ============================================
    t.section('Dual Mode: TSS + HD Coexistence');

    try {
        const { wallet } = NonCustodialWallet.createNewHD('main', 3, 1);

        // TSS signing works
        const msgHash = createHash('sha256').update('test').digest();
        const tssSig = wallet.sign(msgHash);
        const tssVerified = wallet.verify(msgHash, tssSig);
        t.assert(tssVerified === true, 'TSS signing works in HD mode');

        // HD derivation works
        const addr = wallet.getReceivingAddress(0, 0, 'segwit');
        t.assert(addr.address.startsWith('bc1q'), 'HD derivation works in TSS mode');

        // HD message signing works
        const hdSig = wallet.signMessageHD('test', 0, 0, 'segwit');
        t.assert(hdSig !== null, 'HD message signing works alongside TSS');

        // Both keys are different
        const tssKey = wallet.getPublicKey();
        const hdKey = addr.publicKeyBuffer;
        t.assert(!tssKey.equals(hdKey), 'TSS aggregate key differs from HD key');
    } catch (e) {
        t.assert(false, 'Dual mode tests', e.message);
    }

    // ============================================
    // Destroy/Clear Tests
    // ============================================
    t.section('Secure Cleanup');

    try {
        const { wallet } = NonCustodialWallet.createNewHD('main', 3, 1);

        wallet.destroy();
        t.assert(wallet.hasHD() === false, 'hasHD() false after destroy');
        t.assert(wallet.canSign() === false, 'canSign() false after destroy');
        t.assert(wallet.getMnemonic() === null, 'Mnemonic cleared after destroy');
    } catch (e) {
        t.assert(false, 'Cleanup tests', e.message);
    }

    // ============================================
    // Summary
    // ============================================
    const success = t.summary();
    process.exit(success ? 0 : 1);
}

runTests().catch(e => {
    console.error('Test execution failed:', e);
    process.exit(1);
});
