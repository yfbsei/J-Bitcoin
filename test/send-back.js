/**
 * @fileoverview Send testnet funds back to faucet
 * @description Creates and broadcasts a transaction to return tBTC to faucet
 * 
 * Run: node src/wallet/send-back.js
 */

import { CustodialWallet } from '../src/wallet/custodial.js';
import { TransactionBuilder } from '../src/transaction/builder.js';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration
const FAUCET_RETURN_ADDRESS = 'tb1qerzrlxcfu24davlur5sqmgzzgsal6wusda40er';
const FUNDING_TXID = 'a08d87cf4f235b0a7017ad5dcc76b0ce635faa6910ff993159659826bdd56f9e';
const FUNDING_VOUT = 0;
const FUNDING_VALUE = 142751; // satoshis
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
    console.log(' 📤 SEND TESTNET FUNDS BACK TO FAUCET');
    console.log('═'.repeat(60));

    // Load wallet state
    const statePath = join(__dirname, './testnet-data/wallet-state.json');
    if (!existsSync(statePath)) {
        console.error('❌ No wallet state found. Run testnet-test.js first.');
        process.exit(1);
    }

    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    const wallet = CustodialWallet.fromMnemonic('test', state.custodial.mnemonic);

    console.log('\n📍 Wallet restored successfully');

    // Get the address info
    const addrInfo = wallet.getReceivingAddress(0, 0, 'segwit');
    console.log(`   From: ${addrInfo.address}`);
    console.log(`   To: ${FAUCET_RETURN_ADDRESS}`);

    // Check if transaction is confirmed
    console.log('\n⏳ Checking transaction status...');
    const txData = await httpRequest(
        `https://mempool.space/testnet/api/tx/${FUNDING_TXID}`
    );

    if (txData.error) {
        console.error(`❌ Transaction not found: ${txData.error}`);
        process.exit(1);
    }

    console.log(`   TXID: ${FUNDING_TXID}`);
    console.log(`   Status: ${txData.status?.confirmed ? '✅ Confirmed' : '⏳ Pending'}`);
    console.log(`   Value: ${FUNDING_VALUE} sats (${(FUNDING_VALUE / 100000000).toFixed(8)} tBTC)`);

    if (!txData.status?.confirmed) {
        console.log('\n⚠️  Transaction not yet confirmed!');
        console.log('   Wait for at least 1 confirmation before sending.');
        console.log('   Check: https://mempool.space/testnet/tx/' + FUNDING_TXID);
        console.log('\n   Run this script again after confirmation.');
        process.exit(0);
    }

    // Calculate fee and send amount
    // P2WPKH input: ~68 vB, P2WPKH output: ~31 vB, overhead: ~10 vB
    const estimatedVSize = 68 + 31 + 10; // ~109 vB
    const fee = estimatedVSize * FEE_RATE;
    const sendAmount = FUNDING_VALUE - fee;

    console.log(`\n📊 Transaction Details:`);
    console.log(`   Input value: ${FUNDING_VALUE} sats`);
    console.log(`   Fee: ${fee} sats (~${estimatedVSize} vB @ ${FEE_RATE} sat/vB)`);
    console.log(`   Send amount: ${sendAmount} sats`);

    if (sendAmount <= 546) {
        console.error('❌ Amount too small after fees (dust limit)');
        process.exit(1);
    }

    // Build transaction
    console.log('\n🔨 Building transaction...');

    const txBuilder = new TransactionBuilder('test');

    // Add input
    txBuilder.addInput({
        txid: FUNDING_TXID,
        vout: FUNDING_VOUT,
        value: FUNDING_VALUE,
        scriptPubKey: addrInfo.scriptPubKey,
        type: 'p2wpkh',
    });

    // Add output (to faucet)
    txBuilder.addOutput({
        address: FAUCET_RETURN_ADDRESS,
        value: sendAmount,
    });

    // Get private key and sign
    console.log('🔐 Signing transaction...');

    // Get the raw private key buffer (not WIF)
    const addrDetails = wallet.deriveAddress(0, 0, 0, 'segwit');
    const privateKeyBuffer = addrDetails.privateKeyBuffer;

    if (!privateKeyBuffer || privateKeyBuffer.length !== 32) {
        console.error('❌ Failed to get private key');
        process.exit(1);
    }

    try {
        await txBuilder.signAllInputs(privateKeyBuffer);
        console.log('   ✅ Transaction signed');
    } catch (error) {
        console.error(`   ❌ Signing failed: ${error.message}`);
        console.error(error);
        process.exit(1);
    }

    // Build final transaction
    const tx = txBuilder.build();

    // Serialize to hex
    const txHex = txBuilder.toHex();

    if (!txHex) {
        console.error('❌ Failed to build transaction hex');
        console.log('   Transaction object:', JSON.stringify(tx, null, 2));
        process.exit(1);
    }

    console.log(`   Size: ${txHex.length / 2} bytes`);
    console.log(`   Hex: ${txHex.substring(0, 64)}...`);

    // Broadcast
    console.log('\n📡 Broadcasting transaction...');

    try {
        // Try mempool.space first
        const response = await fetch('https://mempool.space/testnet/api/tx', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: txHex,
        });

        const result = await response.text();

        if (response.ok) {
            console.log('   ✅ Transaction broadcast successful!');
            console.log(`   TXID: ${result}`);
            console.log(`   View: https://mempool.space/testnet/tx/${result}`);
        } else {
            console.error(`   ❌ Broadcast failed: ${result}`);

            // Try blockcypher as backup
            console.log('\n   Trying backup API (BlockCypher)...');
            const bcResult = await httpRequest(
                'https://api.blockcypher.com/v1/btc/test3/txs/push',
                {
                    method: 'POST',
                    body: JSON.stringify({ tx: txHex }),
                }
            );

            if (bcResult.tx?.hash) {
                console.log('   ✅ Transaction broadcast via BlockCypher!');
                console.log(`   TXID: ${bcResult.tx.hash}`);
            } else {
                console.error('   ❌ BlockCypher also failed:', JSON.stringify(bcResult));
            }
        }
    } catch (error) {
        console.error(`   ❌ Error: ${error.message}`);
    }

    console.log('\n' + '═'.repeat(60));
    console.log(' Done! Check the explorer for confirmation.');
    console.log('═'.repeat(60));
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
