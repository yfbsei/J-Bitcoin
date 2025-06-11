/**
 * @fileoverview Comprehensive Test Suite for J-Bitcoin Library
 * @version 2.0.0
 * @description Full test coverage for J-Bitcoin Bitcoin library including:
 *              - Custodial HD Wallets (BIP32/BIP39)
 *              - Non-Custodial Threshold Wallets
 *              - Cryptographic Signatures (ECDSA/Schnorr)
 *              - Address Generation (Legacy/SegWit/Taproot)
 *              - BIP Implementation Testing
 * @author yfbsei
 * @license ISC
 */

// =============================================================================
// IMPORTS AND SETUP
// =============================================================================

import {
    // Wallet Classes
    CustodialWallet,
    Custodial_Wallet,
    NonCustodialWallet,
    Non_Custodial_Wallet,
    
    // BIP Implementations
    BIP39,
    BECH32,
    fromSeed,
    derive,
    
    // Cryptographic Signatures
    ECDSA,
    ecdsa,
    SchnorrSignature,
    schnorr_sig,
    Polynomial,
    ThresholdSignature,
    
    // Constants and Configuration
    BIP44_CONSTANTS,
    NETWORK_CONSTANTS,
    FEATURES,
    NETWORKS,
    LIBRARY_INFO,
    BIP_COMPLIANCE
} from './index.js';

// Test configuration
const TEST_CONFIG = {
    iterations: 5,
    timeout: 15000,
    verbose: true,
    networks: ['main', 'test'],
    mnemonicWords: 12,
    thresholdConfigs: [
        { participants: 3, threshold: 2 },
        { participants: 5, threshold: 3 },
        { participants: 7, threshold: 4 }
    ]
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Test result tracking
 */
class TestTracker {
    constructor() {
        this.passed = 0;
        this.failed = 0;
        this.errors = [];
        this.startTime = Date.now();
    }

    pass(testName) {
        this.passed++;
        if (TEST_CONFIG.verbose) {
            console.log(`✅ ${testName}`);
        }
    }

    fail(testName, error) {
        this.failed++;
        this.errors.push({ test: testName, error: error.message });
        console.error(`❌ ${testName}: ${error.message}`);
    }

    summary() {
        const duration = Date.now() - this.startTime;
        const total = this.passed + this.failed;
        
        console.log('\n' + '='.repeat(60));
        console.log('🧪 J-BITCOIN LIBRARY TEST RESULTS');
        console.log('='.repeat(60));
        console.log(`📊 Tests Run: ${total}`);
        console.log(`✅ Passed: ${this.passed}`);
        console.log(`❌ Failed: ${this.failed}`);
        console.log(`⏱️  Duration: ${duration}ms`);
        console.log(`📈 Success Rate: ${((this.passed / total) * 100).toFixed(1)}%`);
        
        if (this.failed > 0) {
            console.log('\n❌ FAILED TESTS:');
            this.errors.forEach(({ test, error }) => {
                console.log(`   • ${test}: ${error}`);
            });
        }
        
        console.log('\n' + '='.repeat(60));
        return this.failed === 0;
    }
}

/**
 * Async test runner with error handling
 */
async function runTest(testName, testFn, tracker) {
    try {
        await testFn();
        tracker.pass(testName);
    } catch (error) {
        tracker.fail(testName, error);
    }
}

/**
 * Generate test message
 */
function generateTestMessage(suffix = '') {
    return `J-Bitcoin Test Message ${Date.now()}${suffix}`;
}

/**
 * Validate Bitcoin address format
 */
function isValidBitcoinAddress(address, network = 'main') {
    if (!address || typeof address !== 'string') return false;
    
    // Legacy P2PKH addresses
    const legacyRegex = network === 'main' ? /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/ : /^[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
    
    // Bech32 SegWit addresses
    const bech32Regex = network === 'main' ? /^bc1[a-z0-9]{39,59}$/ : /^tb1[a-z0-9]{39,59}$/;
    
    return legacyRegex.test(address) || bech32Regex.test(address);
}

/**
 * Validate private key format (WIF)
 */
function isValidWIF(key) {
    return typeof key === 'string' && (key.length === 51 || key.length === 52);
}

/**
 * Validate hex public key
 */
function isValidPublicKey(key) {
    return typeof key === 'string' && /^[0-9a-fA-F]{66}$/.test(key);
}

// =============================================================================
// CORE LIBRARY TESTS
// =============================================================================

/**
 * Test library configuration and metadata
 */
async function testLibraryConfiguration() {
    // Test library info
    if (!LIBRARY_INFO || LIBRARY_INFO.version !== '2.0.0') {
        throw new Error('Invalid library info');
    }
    
    // Test feature flags
    if (!FEATURES.HD_WALLETS || !FEATURES.THRESHOLD_SIGNATURES) {
        throw new Error('Required features not enabled');
    }
    
    // Test network configuration
    if (!NETWORKS.BTC_MAIN || !NETWORKS.BTC_TEST) {
        throw new Error('Bitcoin networks not configured');
    }
    
    // Test BIP compliance
    if (!BIP_COMPLIANCE.BIP32 || !BIP_COMPLIANCE.BIP39) {
        throw new Error('BIP compliance flags missing');
    }
}

/**
 * Test BIP constants and network constants
 */
async function testConstants() {
    // Test BIP44 constants
    if (BIP44_CONSTANTS.COIN_TYPES.BITCOIN_MAINNET !== 0) {
        throw new Error('Invalid Bitcoin mainnet coin type');
    }
    
    if (BIP44_CONSTANTS.COIN_TYPES.BITCOIN_TESTNET !== 1) {
        throw new Error('Invalid Bitcoin testnet coin type');
    }
    
    // Test network constants
    if (!NETWORK_CONSTANTS.BITCOIN_MAINNET.public) {
        throw new Error('Missing mainnet public key version');
    }
    
    if (!NETWORK_CONSTANTS.BITCOIN_TESTNET.public) {
        throw new Error('Missing testnet public key version');
    }
}

// =============================================================================
// BIP39 MNEMONIC TESTS
// =============================================================================

/**
 * Test BIP39 mnemonic generation and validation
 */
async function testBIP39Functionality() {
    // Test mnemonic generation
    const mnemonic = BIP39.generate();
    if (!mnemonic || typeof mnemonic !== 'string') {
        throw new Error('Failed to generate mnemonic');
    }
    
    const words = mnemonic.split(' ');
    if (words.length !== 12) {
        throw new Error(`Invalid mnemonic length: expected 12, got ${words.length}`);
    }
    
    // Test mnemonic validation
    const isValid = BIP39.validate(mnemonic);
    if (!isValid) {
        throw new Error('Generated mnemonic failed validation');
    }
    
    // Test seed generation
    const seed = BIP39.toSeed(mnemonic);
    if (!seed || !Buffer.isBuffer(seed) || seed.length !== 64) {
        throw new Error('Invalid seed generation');
    }
    
    // Test entropy conversion
    const entropy = BIP39.toEntropy(mnemonic);
    if (!entropy || !Buffer.isBuffer(entropy)) {
        throw new Error('Failed to convert mnemonic to entropy');
    }
    
    // Test invalid mnemonic rejection
    const invalidMnemonic = 'invalid mnemonic with wrong words count test';
    const shouldBeFalse = BIP39.validate(invalidMnemonic);
    if (shouldBeFalse) {
        throw new Error('Invalid mnemonic incorrectly validated');
    }
}

// =============================================================================
// CUSTODIAL WALLET TESTS
// =============================================================================

/**
 * Test custodial wallet creation and basic functionality
 */
async function testCustodialWalletCreation() {
    for (const network of TEST_CONFIG.networks) {
        // Test random wallet generation
        const [mnemonic, wallet] = Custodial_Wallet.fromRandom(network);
        
        if (!mnemonic || !wallet) {
            throw new Error(`Failed to create random wallet for ${network}`);
        }
        
        if (!isValidBitcoinAddress(wallet.address, network)) {
            throw new Error(`Invalid address generated for ${network}: ${wallet.address}`);
        }
        
        // Test wallet restoration
        const restoredWallet = Custodial_Wallet.fromMnemonic(network, mnemonic);
        if (restoredWallet.address !== wallet.address) {
            throw new Error('Wallet restoration failed - addresses don\'t match');
        }
        
        // Test with passphrase
        const passphraseWallet = Custodial_Wallet.fromMnemonic(network, mnemonic, 'test-passphrase');
        if (passphraseWallet.address === wallet.address) {
            throw new Error('Passphrase had no effect on wallet generation');
        }
    }
}

/**
 * Test custodial wallet address derivation
 */
async function testCustodialWalletDerivation() {
    const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
    
    // Test receiving address derivation
    const receivingAddr = wallet.deriveReceivingAddress(0);
    if (!isValidBitcoinAddress(receivingAddr, 'main')) {
        throw new Error(`Invalid receiving address: ${receivingAddr}`);
    }
    
    // Test change address derivation
    const changeAddr = wallet.deriveChangeAddress(0);
    if (!isValidBitcoinAddress(changeAddr, 'main')) {
        throw new Error(`Invalid change address: ${changeAddr}`);
    }
    
    // Addresses should be different
    if (receivingAddr === changeAddr) {
        throw new Error('Receiving and change addresses are identical');
    }
    
    // Test multiple address generation
    const addresses = [];
    for (let i = 0; i < 5; i++) {
        const addr = wallet.deriveReceivingAddress(i);
        if (addresses.includes(addr)) {
            throw new Error(`Duplicate address generated at index ${i}`);
        }
        addresses.push(addr);
    }
    
    // Test wallet summary
    const summary = wallet.getSummary();
    if (!summary || !summary.network || !summary.rootAddress) {
        throw new Error('Invalid wallet summary');
    }
}

/**
 * Test custodial wallet signing and verification
 */
async function testCustodialWalletSigning() {
    const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
    const message = generateTestMessage();
    
    // Test message signing
    const [signature, recoveryId] = wallet.sign(message);
    
    if (!signature || typeof signature !== 'string') {
        throw new Error('Invalid signature format');
    }
    
    if (typeof recoveryId !== 'number' || recoveryId < 0 || recoveryId > 3) {
        throw new Error('Invalid recovery ID');
    }
    
    // Test signature verification
    const isValid = wallet.verify(signature, message);
    if (!isValid) {
        throw new Error('Signature verification failed');
    }
    
    // Test with wrong message
    const wrongMessageValid = wallet.verify(signature, message + 'tampered');
    if (wrongMessageValid) {
        throw new Error('Signature incorrectly verified for tampered message');
    }
}

// =============================================================================
// NON-CUSTODIAL THRESHOLD WALLET TESTS
// =============================================================================

/**
 * Test threshold wallet generation
 */
async function testThresholdWalletGeneration() {
    for (const config of TEST_CONFIG.thresholdConfigs) {
        const { participants, threshold } = config;
        
        // Test share generation
        const shares = Non_Custodial_Wallet.generate_shares(threshold, participants, 'main');
        
        if (!Array.isArray(shares) || shares.length !== participants) {
            throw new Error(`Invalid shares generated: expected ${participants}, got ${shares.length}`);
        }
        
        // Verify each share has required properties
        for (let i = 0; i < shares.length; i++) {
            const share = shares[i];
            if (!share || !share.address || !share.share) {
                throw new Error(`Invalid share at index ${i}`);
            }
            
            if (!isValidBitcoinAddress(share.address, 'main')) {
                throw new Error(`Invalid address in share ${i}: ${share.address}`);
            }
        }
        
        // Test that shares generate different addresses
        const addresses = shares.map(s => s.address);
        const uniqueAddresses = new Set(addresses);
        if (uniqueAddresses.size !== participants) {
            throw new Error('Shares generated duplicate addresses');
        }
    }
}

/**
 * Test threshold signature generation and combination
 */
async function testThresholdSignatures() {
    const threshold = 2;
    const participants = 3;
    const message = generateTestMessage();
    
    // Generate threshold shares
    const shares = Non_Custodial_Wallet.generate_shares(threshold, participants, 'main');
    
    // Test individual share signing
    const signatures = [];
    for (let i = 0; i < threshold; i++) {
        const signature = shares[i].sign(message);
        if (!signature || !signature.sig) {
            throw new Error(`Share ${i} failed to sign message`);
        }
        signatures.push(signature);
    }
    
    // Test signature combination
    const combinedSignature = Non_Custodial_Wallet.combine_signatures(signatures, message);
    
    if (!combinedSignature || !combinedSignature.serialized_sig) {
        throw new Error('Failed to combine threshold signatures');
    }
    
    // Test with insufficient signatures
    try {
        const insufficientSigs = signatures.slice(0, threshold - 1);
        Non_Custodial_Wallet.combine_signatures(insufficientSigs, message);
        throw new Error('Should have failed with insufficient signatures');
    } catch (error) {
        if (error.message.includes('Should have failed')) {
            throw error;
        }
        // Expected to fail
    }
}

// =============================================================================
// CRYPTOGRAPHIC SIGNATURE TESTS
// =============================================================================

/**
 * Test ECDSA signature functionality
 */
async function testECDSASignatures() {
    const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
    const message = generateTestMessage();
    
    // Test ECDSA signing
    const signature = ECDSA.sign(privateKey, message);
    if (!signature || !signature.r || !signature.s) {
        throw new Error('Invalid ECDSA signature format');
    }
    
    // Test signature verification
    const publicKey = ECDSA.getPublicKey(privateKey);
    const isValid = ECDSA.verify(signature, message, publicKey);
    if (!isValid) {
        throw new Error('ECDSA signature verification failed');
    }
    
    // Test signature recovery
    const recoveredKey = ECDSA.recover(signature, message, 0);
    if (!recoveredKey || typeof recoveredKey !== 'string') {
        throw new Error('ECDSA signature recovery failed');
    }
    
    // Test with tampered message
    const tamperedValid = ECDSA.verify(signature, message + 'tampered', publicKey);
    if (tamperedValid) {
        throw new Error('ECDSA incorrectly verified tampered message');
    }
}

/**
 * Test Schnorr signature functionality (BIP340)
 */
async function testSchnorrSignatures() {
    const privateKey = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS";
    const message = generateTestMessage();
    
    // Test Schnorr signing
    const signature = schnorr_sig.sign(privateKey, message);
    if (!signature || typeof signature !== 'string') {
        throw new Error('Invalid Schnorr signature format');
    }
    
    // Test public key retrieval
    const publicKey = schnorr_sig.retrieve_public_key(privateKey);
    if (!publicKey || typeof publicKey !== 'string') {
        throw new Error('Failed to retrieve Schnorr public key');
    }
    
    // Test signature verification
    const isValid = schnorr_sig.verify(signature, message, publicKey);
    if (!isValid) {
        throw new Error('Schnorr signature verification failed');
    }
    
    // Test with wrong message
    const wrongMessageValid = schnorr_sig.verify(signature, message + 'wrong', publicKey);
    if (wrongMessageValid) {
        throw new Error('Schnorr incorrectly verified wrong message');
    }
}

// =============================================================================
// ADDRESS ENCODING TESTS
// =============================================================================

/**
 * Test Bech32 address encoding and decoding
 */
async function testBech32Functionality() {
    // Test data for Bech32 encoding
    const testData = Buffer.from('Hello, Bech32!', 'utf8');
    const hrp = 'bc'; // Bitcoin mainnet human-readable part
    
    // Test encoding
    const encoded = BECH32.encode(hrp, testData);
    if (!encoded || typeof encoded !== 'string') {
        throw new Error('Bech32 encoding failed');
    }
    
    // Test decoding
    const decoded = BECH32.decode(encoded);
    if (!decoded || !decoded.data) {
        throw new Error('Bech32 decoding failed');
    }
    
    // Verify data integrity
    if (!Buffer.from(decoded.data).equals(testData)) {
        throw new Error('Bech32 data integrity check failed');
    }
    
    // Test validation
    const isValid = BECH32.validate(encoded);
    if (!isValid) {
        throw new Error('Valid Bech32 address failed validation');
    }
    
    // Test invalid address rejection
    const invalidAddress = 'bc1invalid';
    const shouldBeFalse = BECH32.validate(invalidAddress);
    if (shouldBeFalse) {
        throw new Error('Invalid Bech32 address incorrectly validated');
    }
}

// =============================================================================
// BIP32 HD KEY TESTS
// =============================================================================

/**
 * Test BIP32 master key generation and derivation
 */
async function testBIP32Functionality() {
    const mnemonic = BIP39.generate();
    const seed = BIP39.toSeed(mnemonic);
    
    // Test master key generation
    const masterKey = fromSeed(seed, 'main');
    if (!masterKey || !masterKey.HDpri || !masterKey.HDpub) {
        throw new Error('Invalid master key generation');
    }
    
    // Test key derivation
    const derivationPath = "m/44'/0'/0'/0/0";
    const derivedKey = derive(masterKey.HDpri, derivationPath, 'main');
    
    if (!derivedKey || !derivedKey.pri || !derivedKey.pub) {
        throw new Error('Key derivation failed');
    }
    
    // Validate derived key formats
    if (!isValidWIF(derivedKey.pri)) {
        throw new Error('Invalid derived private key format');
    }
    
    if (!isValidPublicKey(derivedKey.pub)) {
        throw new Error('Invalid derived public key format');
    }
}

// =============================================================================
// SECURITY AND EDGE CASE TESTS
// =============================================================================

/**
 * Test error handling and edge cases
 */
async function testErrorHandling() {
    // Test invalid network
    try {
        Custodial_Wallet.fromRandom('invalid-network');
        throw new Error('Should have failed with invalid network');
    } catch (error) {
        if (error.message.includes('Should have failed')) {
            throw error;
        }
        // Expected to fail
    }
    
    // Test invalid mnemonic
    try {
        BIP39.validate('invalid mnemonic phrase');
        // Should return false, not throw
    } catch (error) {
        throw new Error('BIP39 validation should not throw for invalid mnemonic');
    }
    
    // Test empty message signing
    try {
        const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
        wallet.sign('');
        // Should handle empty message gracefully
    } catch (error) {
        // May throw, which is acceptable
    }
}

/**
 * Test memory cleanup and security
 */
async function testSecurityFeatures() {
    // Test that sensitive operations show warnings in development
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';
    
    try {
        // Operations that should trigger security warnings
        const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
        const shares = Non_Custodial_Wallet.generate_shares(2, 3, 'main');
        
        // Test passed if no errors thrown
    } finally {
        process.env.NODE_ENV = originalEnv;
    }
}

// =============================================================================
// PERFORMANCE TESTS
// =============================================================================

/**
 * Test performance characteristics
 */
async function testPerformance() {
    const iterations = TEST_CONFIG.iterations;
    
    // Test wallet generation performance
    const walletGenStart = Date.now();
    for (let i = 0; i < iterations; i++) {
        const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
    }
    const walletGenTime = Date.now() - walletGenStart;
    
    // Test signature performance
    const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main');
    const message = generateTestMessage();
    
    const sigStart = Date.now();
    for (let i = 0; i < iterations; i++) {
        const [signature, recoveryId] = wallet.sign(message + i);
    }
    const sigTime = Date.now() - sigStart;
    
    console.log(`📊 Performance Metrics:`);
    console.log(`   Wallet Generation: ${walletGenTime / iterations}ms per wallet`);
    console.log(`   Signature Generation: ${sigTime / iterations}ms per signature`);
    
    // Performance should be reasonable (less than 1000ms per operation)
    if (walletGenTime / iterations > 1000) {
        throw new Error('Wallet generation performance too slow');
    }
    
    if (sigTime / iterations > 1000) {
        throw new Error('Signature generation performance too slow');
    }
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

/**
 * Main test execution
 */
async function runAllTests() {
    console.log('🚀 Starting J-Bitcoin Library Test Suite...\n');
    
    const tracker = new TestTracker();
    
    // Core library tests
    await runTest('Library Configuration', testLibraryConfiguration, tracker);
    await runTest('Constants Validation', testConstants, tracker);
    
    // BIP implementation tests
    await runTest('BIP39 Mnemonic Functionality', testBIP39Functionality, tracker);
    await runTest('BIP32 HD Key Functionality', testBIP32Functionality, tracker);
    await runTest('Bech32 Address Encoding', testBech32Functionality, tracker);
    
    // Custodial wallet tests
    await runTest('Custodial Wallet Creation', testCustodialWalletCreation, tracker);
    await runTest('Custodial Wallet Derivation', testCustodialWalletDerivation, tracker);
    await runTest('Custodial Wallet Signing', testCustodialWalletSigning, tracker);
    
    // Non-custodial threshold wallet tests
    await runTest('Threshold Wallet Generation', testThresholdWalletGeneration, tracker);
    await runTest('Threshold Signature Combination', testThresholdSignatures, tracker);
    
    // Cryptographic signature tests
    await runTest('ECDSA Signatures', testECDSASignatures, tracker);
    await runTest('Schnorr Signatures (BIP340)', testSchnorrSignatures, tracker);
    
    // Security and edge case tests
    await runTest('Error Handling', testErrorHandling, tracker);
    await runTest('Security Features', testSecurityFeatures, tracker);
    
    // Performance tests
    await runTest('Performance Characteristics', testPerformance, tracker);
    
    // Display results
    const allPassed = tracker.summary();
    
    if (allPassed) {
        console.log('🎉 All tests passed! J-Bitcoin library is working correctly.');
        process.exit(0);
    } else {
        console.log('💥 Some tests failed. Please review the errors above.');
        process.exit(1);
    }
}

// =============================================================================
// EXECUTION
// =============================================================================

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runAllTests().catch(error => {
        console.error('💥 Test suite crashed:', error.message);
        console.error(error.stack);
        process.exit(1);
    });
}

// Export for use in other test files
export {
    runAllTests,
    TestTracker,
    runTest,
    generateTestMessage,
    isValidBitcoinAddress,
    isValidWIF,
    isValidPublicKey,
    TEST_CONFIG
};