/**
 * @fileoverview Custodial Wallet BTC Standards Compliance Tests
 * @description Tests the CustodialWallet against Bitcoin standards (BIP32/39/44/49/84/86)
 * @version 1.0.0
 * 
 * Run: node src/wallet/custodial-test.js
 */

import { CustodialWallet } from '../src/wallet/custodial.js';
import { createHash } from 'node:crypto';

// Test vectors from BIP39/BIP32 standards
const TEST_VECTORS = {
    // Standard test mnemonic (DO NOT USE IN PRODUCTION)
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',

    // Expected BIP32 master key fingerprint
    expectedMasterFingerprint: '73c5da0a',

    // Expected addresses for different BIP standards (account 0, index 0)
    expectedAddresses: {
        // BIP44 (Legacy P2PKH) - m/44'/0'/0'/0/0
        legacy: {
            mainnet: '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA',
            testnet: 'mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV'
        },
        // BIP49 (Wrapped SegWit P2SH-P2WPKH) - m/49'/0'/0'/0/0
        'wrapped-segwit': {
            mainnet: '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf',
            testnet: '2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2'
        },
        // BIP84 (Native SegWit P2WPKH) - m/84'/0'/0'/0/0
        segwit: {
            mainnet: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
            testnet: 'tb1qcr8te4kr609gcawutmrza0j4xv80jy8zerrg7u'
        },
        // BIP86 (Taproot P2TR) - m/86'/0'/0'/0/0
        taproot: {
            mainnet: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
            testnet: 'tb1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqp3mvzv'
        }
    }
};

class TestRunner {
    constructor() {
        this.passed = 0;
        this.failed = 0;
        this.tests = [];
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
    console.log('Custodial Wallet BTC Standards Compliance Tests');
    console.log('='.repeat(50));

    // ============================================
    // BIP39 Mnemonic Tests
    // ============================================
    t.section('BIP39 Mnemonic Validation');

    try {
        // Test valid mnemonic restoration
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);
        t.assert(wallet !== null, 'Restore from valid mnemonic');
        t.assert(wallet.getMnemonic() === TEST_VECTORS.mnemonic, 'Mnemonic stored correctly');

        // Test new mnemonic generation
        const { wallet: newWallet, mnemonic } = CustodialWallet.createNew('main', 256);
        t.assert(mnemonic.split(' ').length === 24, 'Generate 24-word mnemonic (256-bit)');

        const { wallet: wallet12, mnemonic: mnemonic12 } = CustodialWallet.createNew('main', 128);
        t.assert(mnemonic12.split(' ').length === 12, 'Generate 12-word mnemonic (128-bit)');
    } catch (e) {
        t.assert(false, 'BIP39 tests', e.message);
    }

    // ============================================
    // BIP32 HD Key Derivation Tests
    // ============================================
    t.section('BIP32 HD Key Derivation');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);

        // Test extended keys
        const xprv = wallet.getExtendedPrivateKey();
        const xpub = wallet.getExtendedPublicKey();
        t.assert(xprv && xprv.startsWith('xprv'), 'Extended private key (xprv) generated');
        t.assert(xpub && xpub.startsWith('xpub'), 'Extended public key (xpub) generated');

        // Test testnet keys
        const testWallet = CustodialWallet.fromMnemonic('test', TEST_VECTORS.mnemonic);
        const tprv = testWallet.getExtendedPrivateKey();
        const tpub = testWallet.getExtendedPublicKey();
        t.assert(tprv && tprv.startsWith('tprv'), 'Testnet extended private key (tprv)');
        t.assert(tpub && tpub.startsWith('tpub'), 'Testnet extended public key (tpub)');

        // Test hardened derivation (different accounts)
        const addr0 = wallet.getReceivingAddress(0, 0, 'segwit');
        const addr1 = wallet.getReceivingAddress(1, 0, 'segwit');
        t.assert(addr0.address !== addr1.address, 'Hardened account derivation produces unique addresses');
    } catch (e) {
        t.assert(false, 'BIP32 tests', e.message);
    }

    // ============================================
    // BIP44 Legacy Address Tests (P2PKH)
    // ============================================
    t.section('BIP44 Legacy Addresses (P2PKH)');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);
        const addr = wallet.getReceivingAddress(0, 0, 'legacy');

        t.assert(addr.address.startsWith('1'), 'Mainnet P2PKH starts with 1');
        t.assert(addr.path === "m/44'/0'/0'/0/0", 'Correct BIP44 derivation path');
        t.assert(addr.type === 'legacy', 'Address type is legacy');

        // Check against known test vector
        const expected = TEST_VECTORS.expectedAddresses.legacy.mainnet;
        t.assert(addr.address === expected, `Address matches BIP44 test vector`,
            `Expected: ${expected}, Got: ${addr.address}`);

        // Test testnet
        const testWallet = CustodialWallet.fromMnemonic('test', TEST_VECTORS.mnemonic);
        const testAddr = testWallet.getReceivingAddress(0, 0, 'legacy');
        t.assert(testAddr.address.startsWith('m') || testAddr.address.startsWith('n'),
            'Testnet P2PKH starts with m or n');
    } catch (e) {
        t.assert(false, 'BIP44 tests', e.message);
    }

    // ============================================
    // BIP49 Wrapped SegWit Tests (P2SH-P2WPKH)
    // ============================================
    t.section('BIP49 Wrapped SegWit Addresses (P2SH-P2WPKH)');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);
        const addr = wallet.getReceivingAddress(0, 0, 'wrapped-segwit');

        t.assert(addr.address.startsWith('3'), 'Mainnet P2SH starts with 3');
        t.assert(addr.path === "m/49'/0'/0'/0/0", 'Correct BIP49 derivation path');
        t.assert(addr.type === 'wrapped-segwit', 'Address type is wrapped-segwit');
        t.assert(addr.redeemScript !== null, 'Redeem script present for P2SH');

        // Check against known test vector
        const expected = TEST_VECTORS.expectedAddresses['wrapped-segwit'].mainnet;
        t.assert(addr.address === expected, `Address matches BIP49 test vector`,
            `Expected: ${expected}, Got: ${addr.address}`);
    } catch (e) {
        t.assert(false, 'BIP49 tests', e.message);
    }

    // ============================================
    // BIP84 Native SegWit Tests (P2WPKH)
    // ============================================
    t.section('BIP84 Native SegWit Addresses (P2WPKH)');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);
        const addr = wallet.getReceivingAddress(0, 0, 'segwit');

        t.assert(addr.address.startsWith('bc1q'), 'Mainnet P2WPKH starts with bc1q');
        t.assert(addr.path === "m/84'/0'/0'/0/0", 'Correct BIP84 derivation path');
        t.assert(addr.type === 'segwit', 'Address type is segwit');

        // Check against known test vector
        const expected = TEST_VECTORS.expectedAddresses.segwit.mainnet;
        t.assert(addr.address === expected, `Address matches BIP84 test vector`,
            `Expected: ${expected}, Got: ${addr.address}`);

        // Test testnet
        const testWallet = CustodialWallet.fromMnemonic('test', TEST_VECTORS.mnemonic);
        const testAddr = testWallet.getReceivingAddress(0, 0, 'segwit');
        t.assert(testAddr.address.startsWith('tb1q'), 'Testnet P2WPKH starts with tb1q');
    } catch (e) {
        t.assert(false, 'BIP84 tests', e.message);
    }

    // ============================================
    // BIP86 Taproot Tests (P2TR)
    // ============================================
    t.section('BIP86 Taproot Addresses (P2TR)');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);
        const addr = wallet.getReceivingAddress(0, 0, 'taproot');

        t.assert(addr.address.startsWith('bc1p'), 'Mainnet P2TR starts with bc1p');
        t.assert(addr.path === "m/86'/0'/0'/0/0", 'Correct BIP86 derivation path');
        t.assert(addr.type === 'taproot', 'Address type is taproot');

        // Taproot addresses are 62 characters
        t.assert(addr.address.length === 62, 'Taproot address is 62 characters');

        // Test testnet
        const testWallet = CustodialWallet.fromMnemonic('test', TEST_VECTORS.mnemonic);
        const testAddr = testWallet.getReceivingAddress(0, 0, 'taproot');
        t.assert(testAddr.address.startsWith('tb1p'), 'Testnet P2TR starts with tb1p');
    } catch (e) {
        t.assert(false, 'BIP86 tests', e.message);
    }

    // ============================================
    // Address Uniqueness Tests
    // ============================================
    t.section('Address Uniqueness');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);

        // Generate 20 addresses
        const addresses = wallet.getAddresses(0, 'segwit', 20);
        const uniqueAddresses = new Set(addresses.map(a => a.address));
        t.assert(uniqueAddresses.size === 20, 'All 20 generated addresses are unique');

        // Different types should produce different addresses
        const legacy = wallet.getReceivingAddress(0, 0, 'legacy');
        const segwit = wallet.getReceivingAddress(0, 0, 'segwit');
        const taproot = wallet.getReceivingAddress(0, 0, 'taproot');
        t.assert(legacy.address !== segwit.address, 'Legacy and SegWit addresses differ');
        t.assert(segwit.address !== taproot.address, 'SegWit and Taproot addresses differ');

        // Receiving vs Change addresses
        const receive = wallet.getReceivingAddress(0, 0, 'segwit');
        const change = wallet.getChangeAddress(0, 0, 'segwit');
        t.assert(receive.address !== change.address, 'Receiving and change addresses differ');
    } catch (e) {
        t.assert(false, 'Address uniqueness tests', e.message);
    }

    // ============================================
    // WIF Export/Import Tests
    // ============================================
    t.section('WIF Export/Import');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);

        // Export WIF
        const wif = wallet.exportWIF(0, 0, 0, 'segwit');
        t.assert(wif !== null, 'WIF export successful');
        t.assert(wif.startsWith('K') || wif.startsWith('L'), 'Mainnet compressed WIF prefix (K or L)');
        t.assert(wif.length === 52, 'Compressed WIF is 52 characters');

        // Import WIF
        const wifWallet = CustodialWallet.fromWIF(wif);
        t.assert(wifWallet !== null, 'WIF import successful');

        // Verify same address
        const originalAddr = wallet.getReceivingAddress(0, 0, 'segwit');
        const wifAddr = wifWallet.getReceivingAddress(0, 0, 'segwit');
        t.assert(originalAddr.address === wifAddr.address, 'WIF import produces same address');
    } catch (e) {
        t.assert(false, 'WIF tests', e.message);
    }

    // ============================================
    // Message Signing Tests
    // ============================================
    t.section('Message Signing');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);
        const message = 'Hello Bitcoin!';

        // Legacy message signing
        const sig = wallet.signMessage(message, 0, 0, 'segwit');
        t.assert(sig !== null, 'Message signature created');
        t.assert(sig.signature !== undefined, 'Signature has signature property');

        // Verify signature - pass sig.signature not the whole object
        const addr = wallet.getReceivingAddress(0, 0, 'segwit');
        const verified = wallet.verifyMessage(message, sig.signature, addr.publicKeyBuffer);
        t.assert(verified === true, 'Message signature verified');
    } catch (e) {
        t.assert(false, 'Message signing tests', e.message);
    }

    // ============================================
    // Utility Method Tests
    // ============================================
    t.section('Utility Methods');

    try {
        const wallet = CustodialWallet.fromMnemonic('main', TEST_VECTORS.mnemonic);

        t.assert(wallet.getNetwork() === 'main', 'getNetwork() returns main');
        t.assert(wallet.canSign() === true, 'canSign() returns true with private key');

        const json = wallet.toJSON();
        t.assert(json.network === 'main', 'toJSON() includes network');
        t.assert(json.canSign === true, 'toJSON() includes canSign');

        // Test watch-only wallet
        const xpub = wallet.getExtendedPublicKey();
        const watchOnly = CustodialWallet.fromExtendedKey('main', xpub);
        t.assert(watchOnly.canSign() === false, 'Watch-only wallet cannot sign');
    } catch (e) {
        t.assert(false, 'Utility tests', e.message);
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
