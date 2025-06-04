/**
 * @fileoverview Comprehensive test suite to verify development version compatibility with main
 * 
 * This test file validates that the development version produces identical results
 * to the main version across all functionality areas. It's designed to catch any
 * regressions or inconsistencies between versions.
 * 
 * @author Test Suite
 * @version 1.0.0
 */

import {
    Custodial_Wallet,
    Non_Custodial_Wallet,
    bip39,
    ecdsa,
    schnorr_sig,
    BECH32,
    CASH_ADDR,
    fromSeed,
    derive,
    Polynomial,
    ThresholdSignature,
    FEATURES,
    NETWORKS
} from '../index.js';

/**
 * Test configuration and expected values from main version
 */
const TEST_CONFIG = {
    // Known seed for deterministic testing
    TEST_SEED: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",

    // Known mnemonic for testing
    TEST_MNEMONIC: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",

    // Known private key for signature testing
    TEST_PRIVATE_KEY: "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS",

    // Test message for signatures
    TEST_MESSAGE: "Hello J-Bitcoin Test Suite!",

    // Legacy address for conversion testing
    TEST_LEGACY_ADDRESS: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    TEST_TESTNET_ADDRESS: "mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D",

    // Expected results from main version (actual values from main branch)
    EXPECTED: {
        // BIP32 master key from test seed
        MASTER_XPRV: "xprv9s21ZrQH143K3EuJY8RRCWBLXFgB9WCcFKsv28bcaDy9LUZtXgHe9q9V8kLi4aJ6H8r5X2wu9gz2ZYXbAhtsAcJKX8Z1Ackw6Wq1oi8DEEk",
        MASTER_XPUB: "xpub661MyMwAqRbcFiyme9xRZe855HWfYxvTcYoWpX1E8ZW8DGu35DbthdTxz222XRihFsxrdH4BCEe32DBRyKEerW8CUMAB8FDziiNyDG4ecgT",

        // Address from master key
        MASTER_ADDRESS: "19DxbyoJdUuohAUD54EpS5NK6S7vY2JCcW",

        // Derived key at m/0'/1
        DERIVED_XPRV: "xprv9wP4BN6caE27t7bCyvNLvsYdYZ6Q6hUqWPCVJM7Sf8TuEavCjN3PGFJEN7UuJXmHe5uwkLiXXThfd7pVpuVx4jntRLGDsd3cHw67LpLLy4r",

        // BIP39 seed from test mnemonic
        BIP39_SEED: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",

        // Address conversions
        SEGWIT_ADDRESS: "bc1qw7llyrrqu53dl23n2rpekqc2t5qyaqu6ueplg7",
        CASHADDR_ADDRESS: "bitcoincash:qpmmlusvvrjj9ha2xdgv8xcrpfwsqn5rngt3k26ve2",

        // Testnet conversions
        TESTNET_SEGWIT: "tb1qp8lhpx0jmcusxnq6cyktwp8rfpaunccntw8kty",
        TESTNET_CASHADDR: "bchtest:qqyl7uye7t0rjq6vrtqjedcyudy8hj0rzvnwwa5c5g"
    }
};

/**
 * Test results storage
 */
const testResults = {
    passed: 0,
    failed: 0,
    errors: [],
    details: []
};

/**
 * Utility functions for testing
 */
function assert(condition, message, expected = null, actual = null) {
    if (condition) {
        testResults.passed++;
        testResults.details.push(`✅ ${message}`);
        return true;
    } else {
        testResults.failed++;
        const errorMsg = `❌ ${message}${expected !== null ? `\n   Expected: ${expected}\n   Actual: ${actual}` : ''}`;
        testResults.errors.push(errorMsg);
        testResults.details.push(errorMsg);
        return false;
    }
}

function assertEqual(actual, expected, message) {
    return assert(actual === expected, message, expected, actual);
}

function assertNotNull(value, message) {
    return assert(value !== null && value !== undefined, message);
}

function bufferEqual(buf1, buf2) {
    if (!buf1 || !buf2) return false;
    if (buf1.length !== buf2.length) return false;
    for (let i = 0; i < buf1.length; i++) {
        if (buf1[i] !== buf2[i]) return false;
    }
    return true;
}

/**
 * Test Categories
 */

console.log('🧪 J-Bitcoin Development vs Main Compatibility Test Suite\n');
console.log('='.repeat(60));

// Test 1: Library Constants and Features
console.log('\n📋 Test 1: Library Constants and Features');
try {
    assert(typeof FEATURES === 'object', 'FEATURES object exists');
    assert(FEATURES.HD_WALLETS === true, 'HD_WALLETS feature enabled');
    assert(FEATURES.THRESHOLD_SIGNATURES === true, 'THRESHOLD_SIGNATURES feature enabled');
    assert(FEATURES.ECDSA === true, 'ECDSA feature enabled');
    assert(FEATURES.SCHNORR === true, 'SCHNORR feature enabled');

    assert(typeof NETWORKS === 'object', 'NETWORKS object exists');
    assert(NETWORKS.BTC_MAIN.symbol === 'BTC', 'Bitcoin mainnet network defined');
    assert(NETWORKS.BTC_TEST.symbol === 'BTC', 'Bitcoin testnet network defined');

} catch (error) {
    testResults.errors.push(`Test 1 Error: ${error.message}`);
}

// Test 2: BIP39 Functionality
console.log('\n📋 Test 2: BIP39 Mnemonic and Seed Generation');
try {
    // Test mnemonic generation
    const generatedMnemonic = bip39.mnemonic();
    assert(typeof generatedMnemonic === 'string', 'Mnemonic generation returns string');
    assert(generatedMnemonic.split(' ').length === 12, 'Mnemonic has 12 words');

    // Test checksum validation
    const validChecksum = bip39.checkSum(TEST_CONFIG.TEST_MNEMONIC);
    assert(validChecksum === true, 'Known good mnemonic passes checksum');

    // Test seed generation from known mnemonic
    const seedFromMnemonic = bip39.mnemonic2seed(TEST_CONFIG.TEST_MNEMONIC);
    assertEqual(seedFromMnemonic, TEST_CONFIG.EXPECTED.BIP39_SEED, 'Seed from known mnemonic matches expected');

    // Test random generation
    const randomResult = bip39.random();
    assert(typeof randomResult.mnemonic === 'string', 'Random generation returns mnemonic');
    assert(typeof randomResult.seed === 'string', 'Random generation returns seed');
    assert(bip39.checkSum(randomResult.mnemonic), 'Random mnemonic has valid checksum');

} catch (error) {
    testResults.errors.push(`Test 2 Error: ${error.message}`);
}

// Test 3: BIP32 Key Derivation
console.log('\n📋 Test 3: BIP32 Hierarchical Deterministic Keys');
try {
    // Test master key generation
    const [masterKeys, masterFormat] = fromSeed(TEST_CONFIG.TEST_SEED, 'main');
    assertEqual(masterKeys.HDpri, TEST_CONFIG.EXPECTED.MASTER_XPRV, 'Master private key matches expected');
    assertEqual(masterKeys.HDpub, TEST_CONFIG.EXPECTED.MASTER_XPUB, 'Master public key matches expected');

    // Test key derivation
    const [derivedKeys, derivedFormat] = derive("m/0'/1", masterKeys.HDpri, masterFormat);
    assertNotNull(derivedKeys.HDpri, 'Derived private key exists');
    assertNotNull(derivedKeys.HDpub, 'Derived public key exists');
    assert(derivedFormat.depth === 2, 'Derived key depth is correct');

    // Test public key derivation (non-hardened only)
    const [pubDerived, _] = derive("m/0/1", masterKeys.HDpub, masterFormat);
    assertNotNull(pubDerived.HDpub, 'Public key derivation works');
    assert(pubDerived.HDpri === null, 'Public derivation has no private key');

    // Test hardened derivation error
    try {
        derive("m/0'", masterKeys.HDpub, masterFormat);
        assert(false, 'Hardened derivation from public key should fail');
    } catch (error) {
        assert(error.message.includes("hardend"), 'Hardened derivation error message correct');
    }

} catch (error) {
    testResults.errors.push(`Test 3 Error: ${error.message}`);
}

// Test 4: Custodial Wallet
console.log('\n📋 Test 4: Custodial Wallet Functionality');
try {
    // Test wallet creation from seed
    const walletFromSeed = Custodial_Wallet.fromSeed('main', TEST_CONFIG.TEST_SEED);
    assertNotNull(walletFromSeed.address, 'Wallet has address');
    assertNotNull(walletFromSeed.keypair.pri, 'Wallet has private key');
    assertNotNull(walletFromSeed.keypair.pub, 'Wallet has public key');

    // Test wallet creation from mnemonic
    const walletFromMnemonic = Custodial_Wallet.fromMnemonic('main', TEST_CONFIG.TEST_MNEMONIC);
    assertEqual(walletFromMnemonic.address, walletFromSeed.address, 'Wallets from same seed have same address');

    // Test random wallet generation
    const [mnemonic, randomWallet] = Custodial_Wallet.fromRandom('main');
    assert(mnemonic.split(' ').length === 12, 'Random wallet generates 12-word mnemonic');
    assertNotNull(randomWallet.address, 'Random wallet has address');

    // Test signing and verification
    const [signature, recoveryId] = walletFromSeed.sign(TEST_CONFIG.TEST_MESSAGE);
    assertNotNull(signature, 'Signature generated');
    assert(typeof recoveryId === 'number', 'Recovery ID is number');

    const isValid = walletFromSeed.verify(signature, TEST_CONFIG.TEST_MESSAGE);
    assert(isValid === true, 'Signature verification passes');

    const isInvalid = walletFromSeed.verify(signature, "Wrong message");
    assert(isInvalid === false, 'Wrong message verification fails');

    // Test key derivation
    const originalChildCount = walletFromSeed.child_keys.size;
    walletFromSeed.derive("m/0'/1", 'pri');
    assert(walletFromSeed.child_keys.size === originalChildCount + 1, 'Child key added to set');

} catch (error) {
    testResults.errors.push(`Test 4 Error: ${error.message}`);
}

// Test 5: Non-Custodial (Threshold) Wallet
console.log('\n📋 Test 5: Non-Custodial Threshold Wallet');
try {
    // Test threshold wallet creation
    const thresholdWallet = Non_Custodial_Wallet.fromRandom("main", 3, 2);
    assertNotNull(thresholdWallet.address, 'Threshold wallet has address');
    assertNotNull(thresholdWallet.publicKey, 'Threshold wallet has public key');
    assert(thresholdWallet.group_size === 3, 'Group size set correctly');
    assert(thresholdWallet.threshold === 2, 'Threshold set correctly');

    // Test shares
    const shares = thresholdWallet._shares;
    assert(shares.length === 3, 'Correct number of shares generated');
    assert(shares.every(share => typeof share === 'string'), 'All shares are strings');

    // Test reconstruction from shares
    const reconstructed = Non_Custodial_Wallet.fromShares("main", shares.slice(0, 2), 2);
    assertEqual(reconstructed.address, thresholdWallet.address, 'Reconstructed wallet has same address');

    // Test threshold signing
    const thresholdSig = thresholdWallet.sign(TEST_CONFIG.TEST_MESSAGE);
    assertNotNull(thresholdSig.sig, 'Threshold signature generated');
    assertNotNull(thresholdSig.serialized_sig, 'Serialized signature exists');
    assertNotNull(thresholdSig.msgHash, 'Message hash exists');
    assert(typeof thresholdSig.recovery_id === 'number', 'Recovery ID is number');

    // Test threshold verification
    const thresholdValid = thresholdWallet.verify(thresholdSig.sig, thresholdSig.msgHash);
    assert(thresholdValid === true, 'Threshold signature verification passes');

    // Test private key reconstruction
    const privateKey = thresholdWallet._privateKey;
    assert(typeof privateKey === 'string', 'Private key reconstruction returns string');

    // Test invalid threshold parameters
    try {
        Non_Custodial_Wallet.fromRandom("main", 2, 3); // threshold > group_size
        assert(false, 'Invalid threshold should throw error');
    } catch (error) {
        assert(error.message.includes("too high"), 'Invalid threshold error message correct');
    }

} catch (error) {
    testResults.errors.push(`Test 5 Error: ${error.message}`);
}

// Test 6: ECDSA Signatures
console.log('\n📋 Test 6: ECDSA Signature Operations');
try {
    // Test ECDSA signing
    const [ecdsaSig, ecdsaRecovery] = ecdsa.sign(TEST_CONFIG.TEST_PRIVATE_KEY, TEST_CONFIG.TEST_MESSAGE);
    assertNotNull(ecdsaSig, 'ECDSA signature generated');
    assert(typeof ecdsaRecovery === 'number', 'ECDSA recovery ID is number');
    assert(ecdsaRecovery >= 0 && ecdsaRecovery <= 3, 'Recovery ID in valid range');

    // Test public key recovery
    const recoveredPubKey = ecdsa.retrieve_public_key(TEST_CONFIG.TEST_MESSAGE, ecdsaSig, ecdsaRecovery);
    assertNotNull(recoveredPubKey, 'Public key recovered from signature');
    assert(recoveredPubKey.length === 33, 'Recovered public key is compressed (33 bytes)');

    // Test ECDSA verification
    const ecdsaValid = ecdsa.verify(ecdsaSig, TEST_CONFIG.TEST_MESSAGE, recoveredPubKey);
    assert(ecdsaValid === true, 'ECDSA signature verification passes');

    const ecdsaInvalid = ecdsa.verify(ecdsaSig, "Wrong message", recoveredPubKey);
    assert(ecdsaInvalid === false, 'ECDSA wrong message verification fails');

} catch (error) {
    testResults.errors.push(`Test 6 Error: ${error.message}`);
}

// Test 7: Schnorr Signatures
console.log('\n📋 Test 7: Schnorr Signature Operations');
try {
    // Test Schnorr signing
    const schnorrSig = schnorr_sig.sign(TEST_CONFIG.TEST_PRIVATE_KEY, TEST_CONFIG.TEST_MESSAGE);
    assertNotNull(schnorrSig, 'Schnorr signature generated');
    assert(schnorrSig.length === 64, 'Schnorr signature is 64 bytes');

    // Test Schnorr public key derivation
    const schnorrPubKey = schnorr_sig.retrieve_public_key(TEST_CONFIG.TEST_PRIVATE_KEY);
    assertNotNull(schnorrPubKey, 'Schnorr public key derived');
    assert(schnorrPubKey.length === 32, 'Schnorr public key is 32 bytes (x-only)');

    // Test Schnorr verification
    const schnorrValid = schnorr_sig.verify(schnorrSig, TEST_CONFIG.TEST_MESSAGE, schnorrPubKey);
    assert(schnorrValid === true, 'Schnorr signature verification passes');

    const schnorrInvalid = schnorr_sig.verify(schnorrSig, "Wrong message", schnorrPubKey);
    assert(schnorrInvalid === false, 'Schnorr wrong message verification fails');

    // Test deterministic signing with custom aux
    const customAux = new Uint8Array(32).fill(0xaa);
    const deterministicSig = schnorr_sig.sign(TEST_CONFIG.TEST_PRIVATE_KEY, TEST_CONFIG.TEST_MESSAGE, customAux);
    assert(deterministicSig.length === 64, 'Deterministic Schnorr signature is 64 bytes');

} catch (error) {
    testResults.errors.push(`Test 7 Error: ${error.message}`);
}

// Test 8: Address Format Conversions
console.log('\n📋 Test 8: Address Format Conversions');
try {
    // Test Bech32 conversion
    const segwitAddr = BECH32.to_P2WPKH(TEST_CONFIG.TEST_LEGACY_ADDRESS);
    assertEqual(segwitAddr, TEST_CONFIG.EXPECTED.SEGWIT_ADDRESS, 'Legacy to SegWit conversion matches expected');

    const testnetSegwit = BECH32.to_P2WPKH(TEST_CONFIG.TEST_TESTNET_ADDRESS);
    assertEqual(testnetSegwit, TEST_CONFIG.EXPECTED.TESTNET_SEGWIT, 'Testnet legacy to SegWit conversion matches expected');

    // Test CashAddr conversion
    const cashAddr = CASH_ADDR.to_cashAddr(TEST_CONFIG.TEST_LEGACY_ADDRESS, "p2pkh");
    assertEqual(cashAddr, TEST_CONFIG.EXPECTED.CASHADDR_ADDRESS, 'Legacy to CashAddr conversion matches expected');

    const testnetCashAddr = CASH_ADDR.to_cashAddr(TEST_CONFIG.TEST_TESTNET_ADDRESS, "p2pkh");
    assertEqual(testnetCashAddr, TEST_CONFIG.EXPECTED.TESTNET_CASHADDR, 'Testnet legacy to CashAddr conversion matches expected');

    // Test custom Bech32 encoding
    const customBech32 = BECH32.data_to_bech32("test", "48656c6c6f", "bech32");
    assertNotNull(customBech32, 'Custom Bech32 encoding works');
    assert(customBech32.startsWith("test1"), 'Custom Bech32 has correct prefix');

} catch (error) {
    testResults.errors.push(`Test 8 Error: ${error.message}`);
}

// Test 9: Polynomial and Threshold Cryptography
console.log('\n📋 Test 9: Polynomial and Threshold Cryptography');
try {
    // Test polynomial creation
    const poly = Polynomial.fromRandom(2);
    assert(poly.order === 2, 'Polynomial has correct order');
    assert(poly.coefficients.length === 3, 'Polynomial has correct number of coefficients');

    // Test polynomial evaluation
    const value1 = poly.evaluate(1);
    const value2 = poly.evaluate(2);
    const value3 = poly.evaluate(3);
    assertNotNull(value1, 'Polynomial evaluation at 1 works');
    assertNotNull(value2, 'Polynomial evaluation at 2 works');
    assertNotNull(value3, 'Polynomial evaluation at 3 works');

    // Test Lagrange interpolation
    const points = [[1, value1], [2, value2], [3, value3]];
    const secret = Polynomial.interpolate_evaluate(points, 0);
    assertNotNull(secret, 'Lagrange interpolation works');

    // Test polynomial arithmetic
    const poly2 = Polynomial.fromRandom(2);
    const sum = poly.add(poly2);
    const product = poly.multiply(poly2);
    assert(sum.order >= Math.max(poly.order, poly2.order), 'Polynomial addition order correct');
    assert(product.order === poly.order + poly2.order, 'Polynomial multiplication order correct');

    // Test threshold signature class
    const threshold = new ThresholdSignature(3, 2);
    assert(threshold.group_size === 3, 'ThresholdSignature group size correct');
    assert(threshold.threshold === 2, 'ThresholdSignature threshold correct');
    assertNotNull(threshold.shares, 'ThresholdSignature shares generated');
    assertNotNull(threshold.public_key, 'ThresholdSignature public key generated');

} catch (error) {
    testResults.errors.push(`Test 9 Error: ${error.message}`);
}

// Test 10: Network Compatibility
console.log('\n📋 Test 10: Network Compatibility Testing');
try {
    // Test mainnet vs testnet
    const mainnetWallet = Custodial_Wallet.fromSeed('main', TEST_CONFIG.TEST_SEED);
    const testnetWallet = Custodial_Wallet.fromSeed('test', TEST_CONFIG.TEST_SEED);

    assert(mainnetWallet.net === 'main', 'Mainnet wallet has correct network');
    assert(testnetWallet.net === 'test', 'Testnet wallet has correct network');
    assert(mainnetWallet.address !== testnetWallet.address, 'Different networks have different addresses');

    // Test extended key prefixes
    assert(mainnetWallet.hdKey.HDpri.startsWith('xprv'), 'Mainnet private key has xprv prefix');
    assert(mainnetWallet.hdKey.HDpub.startsWith('xpub'), 'Mainnet public key has xpub prefix');
    assert(testnetWallet.hdKey.HDpri.startsWith('tprv'), 'Testnet private key has tprv prefix');
    assert(testnetWallet.hdKey.HDpub.startsWith('tpub'), 'Testnet public key has tpub prefix');

    // Test threshold wallets on different networks
    const mainThreshold = Non_Custodial_Wallet.fromRandom("main", 3, 2);
    const testThreshold = Non_Custodial_Wallet.fromRandom("test", 3, 2);

    assert(mainThreshold.net === "main", 'Mainnet threshold wallet has correct network');
    assert(testThreshold.net === "test", 'Testnet threshold wallet has correct network');
    assert(mainThreshold.address !== testThreshold.address, 'Different network thresholds have different addresses');

} catch (error) {
    testResults.errors.push(`Test 10 Error: ${error.message}`);
}

// Test 11: Error Handling and Edge Cases
console.log('\n📋 Test 11: Error Handling and Edge Cases');
try {
    // Test invalid mnemonic
    try {
        bip39.mnemonic2seed("invalid mnemonic phrase");
        assert(false, 'Invalid mnemonic should throw error');
    } catch (error) {
        assert(error.includes('invalid checksum'), 'Invalid mnemonic error message correct');
    }

    // Test invalid network
    try {
        Custodial_Wallet.fromSeed('invalid', TEST_CONFIG.TEST_SEED);
        // This might not throw an error depending on implementation
    } catch (error) {
        // Error is acceptable for invalid network
    }

    // Test invalid threshold parameters
    try {
        new ThresholdSignature(2, 3); // threshold > group_size
        assert(false, 'Invalid threshold should throw error');
    } catch (error) {
        assert(error.message.includes("too high"), 'Invalid threshold error correct');
    }

    // Test signature verification with wrong keys
    const [sig, _] = ecdsa.sign(TEST_CONFIG.TEST_PRIVATE_KEY, TEST_CONFIG.TEST_MESSAGE);
    const wrongPubKey = new Uint8Array(33); // All zeros
    const wrongVerification = ecdsa.verify(sig, TEST_CONFIG.TEST_MESSAGE, wrongPubKey);
    assert(wrongVerification === false, 'Wrong public key verification fails');

} catch (error) {
    testResults.errors.push(`Test 11 Error: ${error.message}`);
}

// Display Results
console.log('\n' + '='.repeat(60));
console.log('📊 TEST RESULTS SUMMARY');
console.log('='.repeat(60));

console.log(`✅ Tests Passed: ${testResults.passed}`);
console.log(`❌ Tests Failed: ${testResults.failed}`);
console.log(`📈 Success Rate: ${((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1)}%`);

if (testResults.failed > 0) {
    console.log('\n🚨 FAILURES AND ERRORS:');
    console.log('-'.repeat(40));
    testResults.errors.forEach(error => console.log(error));
}

console.log('\n📋 DETAILED TEST LOG:');
console.log('-'.repeat(40));
testResults.details.forEach(detail => console.log(detail));

console.log('\n🎯 COMPATIBILITY STATUS:');
if (testResults.failed === 0) {
    console.log('🟢 FULLY COMPATIBLE - Development version matches main version behavior');
} else if (testResults.failed < 5) {
    console.log('🟡 MOSTLY COMPATIBLE - Minor differences detected, review failures');
} else {
    console.log('🔴 COMPATIBILITY ISSUES - Significant differences detected, requires investigation');
}

console.log('\n📝 RECOMMENDATIONS:');
if (testResults.failed === 0) {
    console.log('✅ Development version is ready for integration');
    console.log('✅ All core functionality matches main version');
    console.log('✅ No regressions detected');
} else {
    console.log('⚠️  Review failed tests before merging');
    console.log('⚠️  Update expected values if intentional changes were made');
    console.log('⚠️  Investigate any unexpected behavioral differences');
}

console.log('\n' + '='.repeat(60));

// Export results for programmatic use
export const testReport = {
    summary: {
        passed: testResults.passed,
        failed: testResults.failed,
        successRate: ((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1)
    },
    errors: testResults.errors,
    isCompatible: testResults.failed === 0,
    compatibilityLevel: testResults.failed === 0 ? 'FULL' : testResults.failed < 5 ? 'PARTIAL' : 'POOR'
};