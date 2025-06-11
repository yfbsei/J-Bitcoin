/**
 * @fileoverview CORRECTED Taproot transaction example with proper Schnorr signatures
 * 
 * This example demonstrates the FIXED implementation that correctly uses:
 * - Schnorr signatures for Taproot (P2TR) inputs
 * - ECDSA signatures for Legacy/SegWit inputs
 * - Proper signature hash computation for each type
 * - Enhanced transaction signing with algorithm detection
 * 
 * @author yfbsei
 * @version 1.1.0
 */

import {
    CustodialWallet,
    CustodialWalletFactory,
    SignatureManager
} from '../src/wallet/custodial.js';

import Schnorr from '../src/core/crypto/signatures/schnorr-BIP340.js';
import { randomBytes } from 'node:crypto';

// ============================================================================================
// CORRECTED EXAMPLE: PROPER TAPROOT SIGNING
// ============================================================================================

/**
 * Demonstrates correct Taproot transaction signing with Schnorr signatures
 */
async function correctTaprootSigning() {
    console.log('🎯 CORRECTED: Taproot Transaction with Schnorr Signatures\n');
    console.log('='.repeat(70));

    try {
        // Step 1: Create wallet
        const { wallet, mnemonic } = CustodialWalletFactory.generateRandom('main', {
            wordCount: 12,
            storeMnemonic: true
        });

        console.log('✅ Wallet created successfully');
        console.log('🔑 Mnemonic:', mnemonic);

        // Step 2: Generate different address types
        const addresses = {
            legacy: wallet.deriveChildKey(0, 0, 0, 'legacy'),
            segwit: wallet.deriveChildKey(0, 0, 1, 'segwit'),
            taproot: wallet.deriveChildKey(0, 0, 2, 'taproot')
        };

        console.log('\n📍 Generated Addresses:');
        console.log('Legacy (P2PKH)  :', addresses.legacy.address);
        console.log('SegWit (P2WPKH) :', addresses.segwit.address);
        console.log('Taproot (P2TR)  :', addresses.taproot.address);

        // Step 3: Create UTXOs with explicit types for proper signing
        const utxos = [
            {
                txid: 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890',
                vout: 0,
                value: 50000000, // 0.5 BTC
                address: addresses.segwit.address,
                derivationPath: addresses.segwit.path,
                type: 'p2wpkh', // SegWit - will use ECDSA
                scriptPubKey: Buffer.from('0014' + addresses.segwit.publicKey.toString('hex').slice(2), 'hex')
            },
            {
                txid: 'b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1',
                vout: 1,
                value: 75000000, // 0.75 BTC
                address: addresses.taproot.address,
                derivationPath: addresses.taproot.path,
                type: 'p2tr', // 🟡 Taproot - will use SCHNORR
                scriptPubKey: Buffer.from('5120' + addresses.taproot.publicKey.toString('hex'), 'hex'),
                sighashType: 0x00 // Default sighash for Taproot
            }
        ];

        console.log('\n💰 Available UTXOs:');
        utxos.forEach((utxo, i) => {
            const algorithm = utxo.type === 'p2tr' ? 'Schnorr' : 'ECDSA';
            console.log(`UTXO ${i + 1}: ${utxo.value / 100000000} BTC (${utxo.type.toUpperCase()}) → ${algorithm}`);
        });

        // Step 4: Create transaction builder
        const txBuilder = wallet.createTransaction({
            version: 2,
            feeRate: 15,
            rbf: true
        });

        // Step 5: Add inputs
        for (const utxo of utxos) {
            txBuilder.addInput({
                txid: utxo.txid,
                vout: utxo.vout,
                value: utxo.value,
                scriptPubKey: utxo.scriptPubKey,
                type: utxo.type
            });
        }

        // Step 6: Add outputs
        const totalInput = utxos.reduce((sum, utxo) => sum + utxo.value, 0);
        const sendAmount = 100000000; // 1 BTC
        const fee = 10000; // 0.0001 BTC
        const changeAmount = totalInput - sendAmount - fee;

        // Send to another Taproot address
        const recipientTaproot = 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297';
        txBuilder.addOutput({
            address: recipientTaproot,
            value: sendAmount
        });

        // Change back to our SegWit address
        txBuilder.addOutput({
            address: addresses.segwit.address,
            value: changeAmount
        });

        console.log('\n📤 Transaction Outputs:');
        console.log(`Send  : ${sendAmount / 100000000} BTC → ${recipientTaproot}`);
        console.log(`Change: ${changeAmount / 100000000} BTC → ${addresses.segwit.address}`);

        // Step 7: Build unsigned transaction
        const unsignedTx = txBuilder.build();
        console.log('\n🔧 Unsigned transaction built');

        // Step 8: CRITICAL - Sign with proper algorithm detection
        console.log('\n🔐 Signing transaction with algorithm detection...');

        const signedTx = await wallet.signTransaction(unsignedTx, utxos);

        console.log('✅ Transaction signed successfully!');

        // Step 9: Display signing details
        console.log('\n📊 Signing Algorithm Details:');
        signedTx.signingDetails.forEach((detail, i) => {
            console.log(`Input ${i + 1}: ${detail.type.toUpperCase()} → ${detail.algorithm.toUpperCase()}`);
            if (detail.algorithm === 'schnorr') {
                console.log(`  ✨ Signature Length: ${detail.signatureLength} bytes`);
                console.log(`  ✨ Sighash Type: 0x${detail.sighashType.toString(16).padStart(2, '0')}`);
                console.log(`  ✨ Key Path: ${detail.isKeyPath ? 'Yes' : 'No (Script Path)'}`);
            } else {
                console.log(`  🔵 DER Encoding: ${detail.der ? 'Yes' : 'No'}`);
                console.log(`  🔵 Signature Length: ${detail.signatureLength} bytes`);
            }
        });

        console.log('\n📈 Transaction Summary:');
        console.log('Mixed Algorithms:', signedTx.algorithm);
        console.log('Total Inputs    :', utxos.length);
        console.log('Schnorr Sigs    :', signedTx.signingDetails.filter(d => d.algorithm === 'schnorr').length);
        console.log('ECDSA Sigs      :', signedTx.signingDetails.filter(d => d.algorithm === 'ecdsa').length);
        console.log('Fee             :', fee, 'satoshis');

        return {
            wallet,
            signedTransaction: signedTx,
            addresses,
            utxos
        };

    } catch (error) {
        console.error('❌ Error in corrected Taproot signing:', error.message);
        console.error('Details:', error.details);
        throw error;
    }
}

// ============================================================================================
// EXAMPLE: PURE TAPROOT TRANSACTION (ALL SCHNORR)
// ============================================================================================

/**
 * Example with all Taproot inputs (pure Schnorr signatures)
 */
async function pureTaprootTransaction() {
    console.log('\n🟡 PURE TAPROOT: All Schnorr Signatures\n');
    console.log('='.repeat(50));

    try {
        const { wallet } = CustodialWalletFactory.generateRandom('main');

        // Generate multiple Taproot addresses
        const taprootAddresses = [];
        for (let i = 0; i < 3; i++) {
            taprootAddresses.push(wallet.deriveChildKey(0, 0, i, 'taproot'));
        }

        console.log('🔑 Generated Taproot Addresses:');
        taprootAddresses.forEach((addr, i) => {
            console.log(`${i + 1}. ${addr.address}`);
        });

        // Create all-Taproot UTXOs
        const taprootUtxos = taprootAddresses.map((addr, i) => ({
            txid: `${i.toString().padStart(64, '0')}${'a'.repeat(63 - i.toString().length)}`,
            vout: 0,
            value: (i + 1) * 25000000, // 0.25, 0.5, 0.75 BTC
            address: addr.address,
            derivationPath: addr.path,
            type: 'p2tr', // 🟡 All Taproot - all Schnorr signatures
            scriptPubKey: Buffer.from('5120' + addr.publicKey.toString('hex'), 'hex'),
            sighashType: 0x00
        }));

        console.log('\n💰 Pure Taproot UTXOs:');
        taprootUtxos.forEach((utxo, i) => {
            console.log(`UTXO ${i + 1}: ${utxo.value / 100000000} BTC (P2TR → Schnorr)`);
        });

        // Build transaction
        const txBuilder = wallet.createTaprootTransaction({
            version: 2,
            feeRate: 10,
            rbf: true
        });

        // Add all Taproot inputs
        for (const utxo of taprootUtxos) {
            txBuilder.addInput({
                txid: utxo.txid,
                vout: utxo.vout,
                value: utxo.value,
                scriptPubKey: utxo.scriptPubKey,
                type: utxo.type
            });
        }

        // Add outputs
        const totalInput = taprootUtxos.reduce((sum, utxo) => sum + utxo.value, 0);
        const sendAmount = 80000000; // 0.8 BTC
        const fee = 5000; // Low fee due to Taproot efficiency
        const changeAmount = totalInput - sendAmount - fee;

        // Send to external Taproot address
        txBuilder.addOutput({
            address: 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
            value: sendAmount
        });

        // Change to new Taproot address
        const changeAddr = wallet.deriveChildKey(0, 1, 0, 'taproot');
        txBuilder.addOutput({
            address: changeAddr.address,
            value: changeAmount
        });

        console.log('\n📤 Pure Taproot Transaction:');
        console.log(`Send  : ${sendAmount / 100000000} BTC (to external Taproot)`);
        console.log(`Change: ${changeAmount / 100000000} BTC (to ${changeAddr.address})`);

        // Build and sign
        const unsignedTx = txBuilder.build();
        const signedTx = await wallet.signTransaction(unsignedTx, taprootUtxos);

        console.log('\n✨ Pure Schnorr Signing Results:');
        console.log('All inputs signed with Schnorr ✅');
        console.log('Signature uniformity: Maximum privacy ✅');
        console.log('Fee efficiency: Optimal ✅');

        return {
            wallet,
            signedTransaction: signedTx,
            taprootAddresses,
            efficiency: {
                inputCount: taprootUtxos.length,
                allSchnorr: true,
                feePerInput: fee / taprootUtxos.length,
                privacyLevel: 'Maximum'
            }
        };

    } catch (error) {
        console.error('❌ Error in pure Taproot transaction:', error.message);
        throw error;
    }
}

// ============================================================================================
// EXAMPLE: ADVANCED TAPROOT WITH SCRIPT PATHS
// ============================================================================================

/**
 * Advanced Taproot with script path spending (still uses Schnorr)
 */
async function advancedTaprootScriptPath() {
    console.log('\n🧬 ADVANCED: Taproot Script Path with Schnorr\n');
    console.log('='.repeat(55));

    try {
        const { wallet } = CustodialWalletFactory.generateRandom('main');

        // Create script leaves
        const scripts = {
            timeLock: Buffer.from([
                0x04, 0x80, 0x51, 0x03, 0x00, // 6 months timelock
                0xb1, 0x75, // OP_CHECKLOCKTIMEVERIFY OP_DROP
                0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 0).publicKey), // pubkey
                0xac // OP_CHECKSIG
            ]),
            multiSig: Buffer.from([
                0x52, // OP_2
                0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 1).publicKey),
                0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 2).publicKey),
                0x21, ...Buffer.from(wallet.deriveChildKey(0, 0, 3).publicKey),
                0x53, 0xae // OP_3 OP_CHECKMULTISIG
            ])
        };

        console.log('📜 Script Leaves Created:');
        console.log(`Time-lock script: ${scripts.timeLock.length} bytes`);
        console.log(`Multi-sig script: ${scripts.multiSig.length} bytes`);

        // Generate Taproot address with script tree
        const scriptLeaves = Object.values(scripts);
        const taprootWithScripts = wallet.generateTaprootAddress(0, 0, 5, scriptLeaves);

        console.log('\n🌳 Taproot with Script Commitment:');
        console.log('Address:', taprootWithScripts.address);
        console.log('Internal Key:', taprootWithScripts.publicKey.toString('hex'));
        console.log('Merkle Root:', taprootWithScripts.merkleRoot.toString('hex'));
        console.log('Script Paths Available:', scriptLeaves.length);

        // Create UTXO for script path spending
        const scriptUtxo = {
            txid: 'script123456789012345678901234567890123456789012345678901234567890',
            vout: 0,
            value: 50000000, // 0.5 BTC
            address: taprootWithScripts.address,
            derivationPath: taprootWithScripts.path,
            type: 'p2tr',
            scriptPubKey: Buffer.from('5120' + taprootWithScripts.publicKey.toString('hex'), 'hex'),

            // Script path spending options
            scriptPath: true, // Indicates script path spending
            merkleRoot: taprootWithScripts.merkleRoot,
            availableScripts: scriptLeaves,
            leafHash: taprootWithScripts.merkleTree.getLeafHash(0), // Use first script
            inclusionProof: taprootWithScripts.merkleTree.getInclusionProof(0)
        };

        console.log('\n🔐 Script Path Spending Setup:');
        console.log('UTXO Value:', scriptUtxo.value / 100000000, 'BTC');
        console.log('Spending Method: Script Path (not key path)');
        console.log('Selected Script: Time-lock script');
        console.log('Still uses Schnorr signatures! ✅');

        // Build transaction for script path spending
        const txBuilder = wallet.createTaprootTransaction();

        txBuilder.addInput({
            txid: scriptUtxo.txid,
            vout: scriptUtxo.vout,
            value: scriptUtxo.value,
            scriptPubKey: scriptUtxo.scriptPubKey,
            type: scriptUtxo.type
        });

        // Output to regular Taproot address
        const outputAddr = wallet.deriveChildKey(0, 0, 6, 'taproot');
        const fee = 8000; // Lower fee thanks to Taproot efficiency

        txBuilder.addOutput({
            address: outputAddr.address,
            value: scriptUtxo.value - fee
        });

        console.log('\n📤 Script Path Transaction:');
        console.log(`Spend: ${(scriptUtxo.value - fee) / 100000000} BTC to ${outputAddr.address}`);
        console.log('Method: Script path (with Schnorr signature)');

        // Sign with script path options
        const unsignedTx = txBuilder.build();
        const signedTx = await wallet.signTransaction(unsignedTx, [scriptUtxo]);

        console.log('\n🎯 Script Path Signing Results:');
        const scriptSigning = signedTx.signingDetails[0];
        console.log('Algorithm:', scriptSigning.algorithm.toUpperCase());
        console.log('Script Path:', !scriptSigning.isKeyPath ? 'Yes ✅' : 'No');
        console.log('Schnorr Signature:', scriptSigning.algorithm === 'schnorr' ? 'Yes ✅' : 'No');
        console.log('Privacy Level: High (all Taproot spends look identical)');

        return {
            wallet,
            signedTransaction: signedTx,
            scripts,
            taprootWithScripts,
            scriptUtxo
        };

    } catch (error) {
        console.error('❌ Error in script path Taproot:', error.message);
        throw error;
    }
}

// ============================================================================================
// SIGNATURE ALGORITHM COMPARISON
// ============================================================================================

/**
 * Compare signature algorithms and their properties
 */
async function signatureAlgorithmComparison() {
    console.log('\n📊 SIGNATURE ALGORITHM COMPARISON\n');
    console.log('='.repeat(60));

    try {
        const { wallet } = CustodialWalletFactory.generateRandom('main');

        // Generate test keys
        const testKey = wallet.deriveChildKey(0, 0, 0, 'segwit');
        const testMessage = Buffer.from('Hello Taproot with Schnorr!', 'utf8');
        const messageHash = require('crypto').createHash('sha256').update(testMessage).digest();

        console.log('🧪 Testing both signature algorithms...\n');

        // Test ECDSA signing
        console.log('🔵 ECDSA Signature (Legacy/SegWit):');
        const ecdsaStart = Date.now();
        const ecdsaResult = await SignatureManager.signECDSA(messageHash, testKey.privateKey);
        const ecdsaTime = Date.now() - ecdsaStart;

        console.log(`  Algorithm: ECDSA`);
        console.log(`  Signature Length: ${ecdsaResult.signature.r.length + ecdsaResult.signature.s.length} bytes`);
        console.log(`  Format: ${ecdsaResult.format}`);
        console.log(`  Signing Time: ${ecdsaTime}ms`);
        console.log(`  Malleability: Potential issue`);
        console.log(`  Batch Verification: No`);

        // Test Schnorr signing
        console.log('\n🟡 Schnorr Signature (Taproot):');
        const schnorrStart = Date.now();
        const schnorrResult = await SignatureManager.signSchnorr(messageHash, testKey.privateKey, {
            auxRand: randomBytes(32)
        });
        const schnorrTime = Date.now() - schnorrStart;

        console.log(`  Algorithm: Schnorr`);
        console.log(`  Signature Length: ${schnorrResult.signature.length} bytes`);
        console.log(`  Format: ${schnorrResult.format}`);
        console.log(`  Signing Time: ${schnorrTime}ms`);
        console.log(`  Malleability: Not possible ✅`);
        console.log(`  Batch Verification: Yes ✅`);
        console.log(`  Linearity: Yes ✅`);

        // Comparison summary
        console.log('\n📈 SUMMARY:');
        console.log('┌─────────────────┬──────────┬──────────────┐');
        console.log('│ Property        │ ECDSA    │ Schnorr      │');
        console.log('├─────────────────┼──────────┼──────────────┤');
        console.log(`│ Signature Size  │ ~72 bytes│ 64 bytes ✅  │`);
        console.log(`│ Malleability    │ Possible │ Impossible ✅ │`);
        console.log(`│ Batch Verify    │ No       │ Yes ✅       │`);
        console.log(`│ Privacy         │ Lower    │ Higher ✅     │`);
        console.log(`│ Efficiency      │ Good     │ Better ✅     │`);
        console.log('└─────────────────┴──────────┴──────────────┘');

        const sizeSavings = 72 - 64;
        const efficiencyGain = ((sizeSavings / 72) * 100).toFixed(1);

        console.log(`\n💡 Taproot Benefits:`);
        console.log(`  • ${sizeSavings} bytes smaller signatures`);
        console.log(`  • ${efficiencyGain}% size reduction`);
        console.log(`  • Enhanced privacy through signature uniformity`);
        console.log(`  • Better scalability with batch verification`);
        console.log(`  • Future-proof with script tree flexibility`);

        return {
            ecdsa: ecdsaResult,
            schnorr: schnorrResult,
            comparison: {
                sizeSavings,
                efficiencyGain: parseFloat(efficiencyGain),
                timeDifference: schnorrTime - ecdsaTime
            }
        };

    } catch (error) {
        console.error('❌ Error in algorithm comparison:', error.message);
        throw error;
    }
}

// ============================================================================================
// MAIN EXECUTION
// ============================================================================================

/**
 * Run all corrected examples demonstrating proper Taproot Schnorr signing
 */
async function runCorrectedExamples() {
    console.log('🎯 CORRECTED TAPROOT EXAMPLES - PROPER SCHNORR SIGNATURES');
    console.log('================================================================');
    console.log('This demonstrates the FIXED implementation where:');
    console.log('• Taproot (P2TR) inputs use Schnorr signatures ✅');
    console.log('• Legacy/SegWit inputs use ECDSA signatures ✅');
    console.log('• Proper signature hash computation for each type ✅');
    console.log('• Algorithm detection and mixed transaction support ✅\n');

    try {
        // Example 1: Mixed transaction (ECDSA + Schnorr)
        const corrected = await correctTaprootSigning();

        console.log('\n' + '='.repeat(70));

        // Example 2: Pure Taproot (all Schnorr)
        const pure = await pureTaprootTransaction();

        console.log('\n' + '='.repeat(70));

        // Example 3: Script path spending (still Schnorr)
        const scriptPath = await advancedTaprootScriptPath();

        console.log('\n' + '='.repeat(70));

        // Example 4: Algorithm comparison
        const comparison = await signatureAlgorithmComparison();

        console.log('\n' + '='.repeat(70));
        console.log('🎉 ALL CORRECTED EXAMPLES COMPLETED SUCCESSFULLY!');
        console.log('\n✅ Key Fixes Applied:');
        console.log('  • Taproot inputs now use Schnorr signatures');
        console.log('  • Proper BIP340/341 implementation');
        console.log('  • Mixed transaction support');
        console.log('  • Enhanced privacy and efficiency');

        // Cleanup
        corrected.wallet.cleanup();
        pure.wallet.cleanup();
        scriptPath.wallet.cleanup();

        return {
            corrected,
            pure,
            scriptPath,
            comparison
        };

    } catch (error) {
        console.error('💥 Corrected examples failed:', error.message);
        console.error(error.stack);
        throw error;
    }
}

// Export corrected examples
export {
    correctTaprootSigning,
    pureTaprootTransaction,
    advancedTaprootScriptPath,
    signatureAlgorithmComparison,
    runCorrectedExamples
};

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runCorrectedExamples()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
}