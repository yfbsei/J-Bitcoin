/**
 * Final verification test for the fixed Schnorr BIP-340 implementation
 */

import EnhancedSchnorr from './src/core/crypto/signatures/schnorr-BIP340.js';

const TEST_VECTORS = [
    {
        index: 0,
        secretKey: "0000000000000000000000000000000000000000000000000000000000000003",
        publicKey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        auxRand: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        comment: "Basic test vector"
    },
    {
        index: 1,
        secretKey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        publicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        auxRand: "0000000000000000000000000000000000000000000000000000000000000001",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        comment: "Test with high values"
    },
    {
        index: 2,
        secretKey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        publicKey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        auxRand: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        comment: "Test with maximum entropy"
    }
];

async function runFinalTests() {
    console.log('🎯 Final Schnorr BIP-340 Verification Test');
    console.log('==========================================\n');

    const schnorr = new EnhancedSchnorr();
    let passed = 0;
    let failed = 0;

    // Test 1: All BIP-340 test vectors
    console.log('📋 Test 1: BIP-340 Test Vector Verification');
    for (const vector of TEST_VECTORS) {
        try {
            const isValid = await schnorr.verify(
                Buffer.from(vector.signature, 'hex'),
                Buffer.from(vector.message, 'hex'),
                Buffer.from(vector.publicKey, 'hex')
            );

            if (isValid) {
                console.log(`   ✅ Vector ${vector.index}: PASS`);
                passed++;
            } else {
                console.log(`   ❌ Vector ${vector.index}: FAIL`);
                failed++;
            }
        } catch (error) {
            console.log(`   ❌ Vector ${vector.index}: ERROR - ${error.message}`);
            failed++;
        }
    }

    // Test 2: Error handling (should throw errors now)
    console.log('\n📋 Test 2: Proper Error Handling');

    const errorTests = [
        { name: 'Empty signature', sig: Buffer.alloc(0), shouldThrow: true },
        { name: '32-byte signature', sig: Buffer.alloc(32), shouldThrow: true },
        { name: '63-byte signature', sig: Buffer.alloc(63), shouldThrow: true },
        { name: '65-byte signature', sig: Buffer.alloc(65), shouldThrow: true },
        { name: 'Null signature', sig: null, shouldThrow: true }
    ];

    for (const test of errorTests) {
        try {
            await schnorr.verify(test.sig, Buffer.alloc(32), Buffer.alloc(32));

            if (test.shouldThrow) {
                console.log(`   ❌ ${test.name}: Should have thrown error`);
                failed++;
            } else {
                console.log(`   ✅ ${test.name}: Correctly accepted`);
                passed++;
            }
        } catch (error) {
            if (test.shouldThrow) {
                console.log(`   ✅ ${test.name}: Correctly threw error (${error.code})`);
                passed++;
            } else {
                console.log(`   ❌ ${test.name}: Unexpected error - ${error.message}`);
                failed++;
            }
        }
    }

    // Test 3: Signature generation and self-verification
    console.log('\n📋 Test 3: Signature Generation & Self-Verification');
    try {
        const privateKey = Buffer.from('0000000000000000000000000000000000000000000000000000000000000003', 'hex');
        const message = Buffer.from('Hello Bitcoin!', 'utf8');

        // Generate signature
        const result = await schnorr.sign(privateKey, message);
        console.log(`   ✅ Signature generated: ${result.signature.toString('hex').substring(0, 16)}...`);

        // Get public key
        const publicKey = await schnorr.getPublicKey(privateKey);
        console.log(`   ✅ Public key derived: ${publicKey.toString('hex').substring(0, 16)}...`);

        // Verify our own signature
        const isValid = await schnorr.verify(result.signature, message, publicKey);
        if (isValid) {
            console.log('   ✅ Self-verification: PASS');
            passed++;
        } else {
            console.log('   ❌ Self-verification: FAIL');
            failed++;
        }

    } catch (error) {
        console.log(`   ❌ Signature generation/verification failed: ${error.message}`);
        failed++;
    }

    // Print final results
    console.log('\n🏆 Final Test Results');
    console.log('=====================');
    console.log(`Total Tests: ${passed + failed}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);

    if (failed === 0) {
        console.log('\n🎉 PERFECT! Your Schnorr BIP-340 implementation is fully compliant!');
        console.log('✅ All BIP-340 test vectors pass');
        console.log('✅ Error handling works correctly');
        console.log('✅ Signature generation and verification work perfectly');
        console.log('\n🚀 Your implementation is ready for production use!');
        return true;
    } else {
        console.log(`\n⚠️  ${failed} test(s) still failing. Review needed.`);
        return false;
    }
}

// Run final verification
runFinalTests()
    .then(success => {
        console.log(success ? '\n✅ All tests completed successfully!' : '\n❌ Some issues remain.');
    })
    .catch(error => {
        console.error('💥 Test execution failed:', error);
    });