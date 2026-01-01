/**
 * @fileoverview Send TSS (Non-Custodial) testnet funds
 * @description Creates a transaction from the non-custodial wallet with 2 outputs:
 *              - Half to faucet return address
 *              - Half to non-custodial Taproot address for further testing
 * 
 * Run: node src/wallet/send-back-tss.js
 */

import { NonCustodialWallet } from '../src/wallet/non-custodial.js';
import { TransactionBuilder } from '../src/transaction/builder.js';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration
const FAUCET_RETURN_ADDRESS = 'tb1qn9rvr53m7qvrpysx48svuxsgahs88xfsskx367';
const TAPROOT_TSS_ADDRESS = 'tb1pmcmdej5hxanenafsgv9kgq8z0dsckyk9hel37prtt4y6egad6jtsgm6vsd';
const FUNDING_TXID = 'ea459f93ae859ea24d9b19af99b66cbe88b186ef7fc3995f78328bc8b60b8e04';
const FUNDING_VOUT = 0;
const FUNDING_VALUE = 122087; // 0.00122087 BTC in satoshis
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
    console.log(' 📤 TSS NON-CUSTODIAL WALLET TRANSACTION');
    console.log('═'.repeat(60));
    console.log(' Wallet: Non-Custodial (Threshold Signature Scheme)');
    console.log(' Outputs: 2 (Faucet + Taproot TSS)');
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
    console.log(`   TSS Config: ${state.nonCustodial.n}-of-${state.nonCustodial.n} (t=${state.nonCustodial.t})`);

    // Get the SegWit address info
    const addrInfo = wallet.getReceivingAddress(0, 0, 'segwit');
    console.log(`   From: ${addrInfo.address}`);
    console.log(`   To[0]: ${FAUCET_RETURN_ADDRESS} (Faucet)`);
    console.log(`   To[1]: ${TAPROOT_TSS_ADDRESS.substring(0, 20)}... (Taproot TSS)`);

    // Check if transaction is confirmed
    console.log('\n⏳ Checking transaction status...');
    const txData = await httpRequest(
        `https://mempool.space/testnet4/api/tx/${FUNDING_TXID}`
    );

    if (typeof txData === 'string') {
        console.error(`❌ Transaction not found: ${txData}`);
        console.log(`   Check: https://mempool.space/testnet4/tx/${FUNDING_TXID}`);
        process.exit(1);
    }

    console.log(`   TXID: ${FUNDING_TXID}`);
    console.log(`   Status: ${txData.status?.confirmed ? '✅ Confirmed' : '⏳ Pending'}`);
    console.log(`   Value: ${FUNDING_VALUE} sats (${(FUNDING_VALUE / 100000000).toFixed(8)} tBTC)`);

    if (!txData.status?.confirmed) {
        console.log('\n⚠️  Transaction not yet confirmed!');
        console.log('   Check: https://mempool.space/testnet4/tx/' + FUNDING_TXID);
        process.exit(0);
    }

    // Calculate fee and amounts
    // P2WPKH input: ~68 vB, 2x P2WPKH outputs: ~62 vB, overhead: ~10 vB
    const estimatedVSize = 68 + 31 + 43 + 10; // P2WPKH input + P2WPKH out + P2TR out + overhead
    const fee = estimatedVSize * FEE_RATE;
    const totalAfterFee = FUNDING_VALUE - fee;
    const halfAmount = Math.floor(totalAfterFee / 2);
    const faucetAmount = halfAmount;
    const taprootAmount = totalAfterFee - halfAmount; // Remainder goes to taproot

    console.log(`\n📊 Transaction Details:`);
    console.log(`   Input value: ${FUNDING_VALUE} sats`);
    console.log(`   Fee: ${fee} sats (~${estimatedVSize} vB @ ${FEE_RATE} sat/vB)`);
    console.log(`   Output[0] Faucet: ${faucetAmount} sats`);
    console.log(`   Output[1] Taproot TSS: ${taprootAmount} sats`);

    if (faucetAmount <= 546 || taprootAmount <= 546) {
        console.error('❌ Output amounts too small (dust limit)');
        process.exit(1);
    }

    // Build transaction
    console.log('\n🔨 Building transaction...');

    const txBuilder = new TransactionBuilder('test');

    // Add input from non-custodial SegWit address
    txBuilder.addInput({
        txid: FUNDING_TXID,
        vout: FUNDING_VOUT,
        value: FUNDING_VALUE,
        scriptPubKey: addrInfo.scriptPubKey,
        type: 'p2wpkh',
    });

    // Output 1: Faucet return (SegWit)
    txBuilder.addOutput({
        address: FAUCET_RETURN_ADDRESS,
        value: faucetAmount,
    });

    // Output 2: Taproot TSS address for next test
    txBuilder.addOutput({
        address: TAPROOT_TSS_ADDRESS,
        value: taprootAmount,
    });

    // Sign with non-custodial wallet
    console.log('🔐 Signing with Non-Custodial Wallet...');

    try {
        // Use the signTransaction method with input info
        await wallet.signTransaction(txBuilder, [
            { account: 0, change: 0, index: 0, type: 'segwit' }
        ]);
        console.log('   ✅ Transaction signed with HD-derived key');
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
    console.log('\n📡 Broadcasting transaction...');

    try {
        const response = await fetch('https://mempool.space/testnet4/api/tx', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: txHex,
        });

        const result = await response.text();

        if (response.ok) {
            console.log('   ✅ Transaction broadcast successful!');
            console.log(`   TXID: ${result}`);
            console.log(`   View: https://mempool.space/testnet4/tx/${result}`);

            console.log('\n📋 Next Steps:');
            console.log(`   • Faucet received: ${faucetAmount} sats`);
            console.log(`   • Taproot TSS address funded: ${taprootAmount} sats`);
            console.log('   • Wait for confirmation, then test Taproot TSS signing!');
        } else {
            console.error(`   ❌ Broadcast failed: ${result}`);
        }
    } catch (error) {
        console.error(`   ❌ Error: ${error.message}`);
    }

    console.log('\n' + '═'.repeat(60));
    console.log(' Done! Non-custodial transaction sent.');
    console.log('═'.repeat(60));
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
