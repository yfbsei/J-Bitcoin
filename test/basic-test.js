import { Custodial_Wallet, Non_Custodial_Wallet, BECH32, CASH_ADDR } from '../index.js';

console.log('🧪 Testing J-Bitcoin Library...\n');

// Test 1: Custodial Wallet
console.log('📋 Test 1: Custodial Wallet');
try {
    const [mnemonic, wallet] = Custodial_Wallet.fromRandom('test');
    console.log('✅ Wallet created successfully');
    console.log('   Mnemonic:', mnemonic.split(' ').slice(0, 3).join(' ') + '...');
    console.log('   Address:', wallet.address);

    // Test signing
    const [signature, recovery] = wallet.sign("Test message");
    const isValid = wallet.verify(signature, "Test message");
    console.log('✅ Signature test:', isValid ? 'PASSED' : 'FAILED');

} catch (error) {
    console.log('❌ Custodial wallet test failed:', error.message);
}

// Test 2: Threshold Signatures
console.log('\n📋 Test 2: Threshold Signatures');
try {
    const thresholdWallet = Non_Custodial_Wallet.fromRandom("test", 3, 2);
    console.log('✅ Threshold wallet created (2-of-3)');
    console.log('   Address:', thresholdWallet.address);
    console.log('   Shares count:', thresholdWallet._shares.length);

    // Test threshold signing
    const signature = thresholdWallet.sign("Threshold test");
    console.log('✅ Threshold signature created');

} catch (error) {
    console.log('❌ Threshold signature test failed:', error.message);
}

// Test 3: Address Conversion
console.log('\n📋 Test 3: Address Conversion');
try {
    const testAddr = "mgRpP3zP1hmxyoeYJgfbcmN3c2Qsurw48D"; // Testnet address
    const segwit = BECH32.to_P2WPKH(testAddr);
    const cashAddr = CASH_ADDR.to_cashAddr(testAddr);

    console.log('✅ Address conversion successful');
    console.log('   Original:', testAddr);
    console.log('   SegWit:', segwit);
    console.log('   CashAddr:', cashAddr);

} catch (error) {
    console.log('❌ Address conversion test failed:', error.message);
}

console.log('\n🎉 Testing completed!');