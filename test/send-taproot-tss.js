/**
 * @fileoverview Send from Taproot TSS to SegWit TSS address
 * @description Tests Non-Custodial Taproot (P2TR) signing with Schnorr/BIP341
 * 
 * Run: node src/wallet/send-taproot-tss.js
 */

import { NonCustodialWallet } from '../src/wallet/non-custodial.js';
import { TransactionBuilder } from '../src/transaction/builder.js';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration
const SEGWIT_TSS_ADDRESS = 'tb1qgc6a9v43ukgldhkavc6c2pfyym4nuf577k6qas';
const FUNDING_TXID = 'babb3977328d530770ea11c5a2143ed6963f72e5873ddee7a3bd4c0fea0f6899';
const FUNDING_VOUT = 1; // Second output was the Taproot TSS
const FUNDING_VALUE = 60892; // satoshis
const FEE_RATE = 2; // sat/vB

async function httpRequest(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: { 'Content-Type': 'application/json', ...options.headers },
    });
    const text = await response.text();
    try {
        return JSON.parse(text);
    } catch {
        return text;
    }
}

async function main() {
    console.log('═'.repeat(60));
    console.log(' 📤 TAPROOT TSS → SEGWIT TSS TRANSACTION');
    console.log('═'.repeat(60));
    console.log(' Signing: BIP340 Schnorr + BIP341 Sighash');
    console.log(' Wallet: Non-Custodial (Threshold Signature Scheme)');
    console.log('═'.repeat(60));

    // Load wallet state
    const statePath = join(__dirname, './testnet-data/wallet-state.json');
    if (!existsSync(statePath)) {
        console.error('❌ No wallet state found. Run testnet-test.js first.');
        process.exit(1);
    }

    const state = JSON.parse(readFileSync(statePath, 'utf8'));

    // Restore non-custodial wallet
    const wallet = NonCustodialWallet.fromMnemonic(
        'test',
        state.nonCustodial.mnemonic,
        state.nonCustodial.n,
        state.nonCustodial.t
    );

    console.log('\n📍 Non-Custodial Wallet restored');
    console.log(`   TSS Config: ${state.nonCustodial.n}-of-${state.nonCustodial.n}`);

    // Get the Taproot address info (source)
    const taprootInfo = wallet.getReceivingAddress(0, 0, 'taproot');
    console.log(`   From (Taproot): ${taprootInfo.address}`);
    console.log(`   To (SegWit): ${SEGWIT_TSS_ADDRESS}`);

    // Check if transaction is confirmed
    console.log('\n⏳ Checking transaction status...');
    const txData = await httpRequest(
        `https://mempool.space/testnet4/api/tx/${FUNDING_TXID}`
    );

    if (typeof txData === 'string') {
        console.error(`❌ Transaction not found: ${txData}`);
        process.exit(1);
    }

    console.log(`   TXID: ${FUNDING_TXID}`);
    console.log(`   Status: ${txData.status?.confirmed ? '✅ Confirmed' : '⏳ Pending'}`);

    // Get actual value from the UTXO
    const actualValue = txData.vout[FUNDING_VOUT]?.value;
    console.log(`   Value: ${actualValue} sats`);

    if (!txData.status?.confirmed) {
        console.log('\n⚠️  Transaction not yet confirmed!');
        console.log('   Check: https://mempool.space/testnet4/tx/' + FUNDING_TXID);
        process.exit(0);
    }

    // Calculate fee
    // P2TR input: ~57.5 vB, P2WPKH output: ~31 vB, overhead: ~10 vB
    const estimatedVSize = 58 + 31 + 10; // ~99 vB
    const fee = estimatedVSize * FEE_RATE;
    const sendAmount = actualValue - fee;

    console.log(`\n📊 Transaction Details:`);
    console.log(`   Input value: ${actualValue} sats`);
    console.log(`   Fee: ${fee} sats (~${estimatedVSize} vB @ ${FEE_RATE} sat/vB)`);
    console.log(`   Send amount: ${sendAmount} sats`);

    if (sendAmount <= 546) {
        console.error('❌ Amount too small (dust limit)');
        process.exit(1);
    }

    // Build transaction
    console.log('\n🔨 Building Taproot transaction...');

    const txBuilder = new TransactionBuilder('test');

    // Add Taproot input
    txBuilder.addInput({
        txid: FUNDING_TXID,
        vout: FUNDING_VOUT,
        value: actualValue,
        scriptPubKey: taprootInfo.scriptPubKey,
        type: 'p2tr', // Triggers Schnorr/BIP341 signing
    });

    // Output to SegWit TSS address
    txBuilder.addOutput({
        address: SEGWIT_TSS_ADDRESS,
        value: sendAmount,
    });

    // Sign with Schnorr
    console.log('🔐 Signing with Schnorr (BIP340)...');

    try {
        // Get private key for Taproot address
        const taprootDerived = wallet.deriveAddress(0, 0, 0, 'taproot');

        if (!taprootDerived.privateKeyBuffer) {
            throw new Error('No private key available for Taproot address');
        }

        await txBuilder.signAllInputs(taprootDerived.privateKeyBuffer);
        console.log('   ✅ Schnorr signature created');
    } catch (error) {
        console.error(`   ❌ Signing failed: ${error.message}`);
        console.error(error);
        process.exit(1);
    }

    // Build final transaction
    const tx = txBuilder.build();
    const txHex = txBuilder.toHex();

    if (!txHex) {
        console.error('❌ Failed to build transaction hex');
        process.exit(1);
    }

    console.log(`   Size: ${txHex.length / 2} bytes`);
    console.log(`   vSize: ${txBuilder.getVirtualSize()} vB`);
    console.log(`   Hex: ${txHex.substring(0, 64)}...`);

    // Broadcast
    console.log('\n📡 Broadcasting Taproot transaction...');

    try {
        const response = await fetch('https://mempool.space/testnet4/api/tx', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: txHex,
        });

        const result = await response.text();

        if (response.ok) {
            console.log('   ✅ Taproot TSS transaction broadcast successful!');
            console.log(`   TXID: ${result}`);
            console.log(`   View: https://mempool.space/testnet4/tx/${result}`);
        } else {
            console.error(`   ❌ Broadcast failed: ${result}`);
        }
    } catch (error) {
        console.error(`   ❌ Error: ${error.message}`);
    }

    console.log('\n' + '═'.repeat(60));
    console.log(' Done! Taproot TSS → SegWit TSS complete.');
    console.log('═'.repeat(60));
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
