/**
 * @fileoverview Send Taproot testnet funds back to faucet
 * @description Creates and broadcasts a P2TR transaction using Schnorr/BIP341 signing
 * 
 * Run: node src/wallet/send-back-taproot.js
 */

import { CustodialWallet } from '../src/wallet/custodial.js';
import { TransactionBuilder } from '../src/transaction/builder.js';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration for Taproot transaction
const FAUCET_RETURN_ADDRESS = 'tb1qn9rvr53m7qvrpysx48svuxsgahs88xfsskx367';
const FUNDING_TXID = '82d441489c6b3ecd537904e089c0fd89ec65e171dd7cb90d22317b4f7e59633c';
const FUNDING_VOUT = 0;
const FUNDING_VALUE = 118395; // 0.00118395 BTC in satoshis
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
    console.log(' 📤 SEND TAPROOT (P2TR) FUNDS BACK TO FAUCET');
    console.log('═'.repeat(60));
    console.log(' Signing: BIP340 Schnorr + BIP341 Sighash');
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

    // Get the Taproot address info
    const addrInfo = wallet.getReceivingAddress(0, 0, 'taproot');
    console.log(`   From: ${addrInfo.address}`);
    console.log(`   To: ${FAUCET_RETURN_ADDRESS}`);
    console.log(`   Type: P2TR (Taproot key-path spend)`);

    // Check if transaction is confirmed
    console.log('\n⏳ Checking transaction status...');
    const txData = await httpRequest(
        `https://mempool.space/testnet4/api/tx/${FUNDING_TXID}`
    );

    if (typeof txData === 'string' && txData.includes('not found')) {
        console.log('   Transaction still propagating...');
        console.log('   Waiting 10 seconds...');
        await new Promise(r => setTimeout(r, 10000));
    }

    const txData2 = await httpRequest(
        `https://mempool.space/testnet4/api/tx/${FUNDING_TXID}`
    );

    if (typeof txData2 === 'string') {
        console.error(`❌ Transaction not found yet. Try again in a minute.`);
        console.log(`   Check: https://mempool.space/testnet/tx/${FUNDING_TXID}`);
        process.exit(1);
    }

    console.log(`   TXID: ${FUNDING_TXID}`);
    console.log(`   Status: ${txData2.status?.confirmed ? '✅ Confirmed' : '⏳ Pending'}`);
    console.log(`   Value: ${FUNDING_VALUE} sats (${(FUNDING_VALUE / 100000000).toFixed(8)} tBTC)`);

    if (!txData2.status?.confirmed) {
        console.log('\n⚠️  Transaction not yet confirmed!');
        console.log('   Wait for at least 1 confirmation before sending.');
        console.log('   Check: https://mempool.space/testnet4/tx/' + FUNDING_TXID);
        console.log('\n   Run this script again after confirmation.');
        process.exit(0);
    }

    // Calculate fee and send amount
    // P2TR input: ~57.5 vB, P2WPKH output: ~31 vB, overhead: ~10 vB
    const estimatedVSize = 58 + 31 + 10; // ~99 vB for P2TR
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
    console.log('\n🔨 Building Taproot transaction...');

    const txBuilder = new TransactionBuilder('test');

    // Add Taproot input
    txBuilder.addInput({
        txid: FUNDING_TXID,
        vout: FUNDING_VOUT,
        value: FUNDING_VALUE,
        scriptPubKey: addrInfo.scriptPubKey,
        type: 'p2tr', // This triggers Schnorr/BIP341 signing
    });

    // Add output (to faucet - SegWit address)
    txBuilder.addOutput({
        address: FAUCET_RETURN_ADDRESS,
        value: sendAmount,
    });

    // Get private key and sign with Schnorr
    console.log('🔐 Signing with Schnorr (BIP340)...');

    // Get the raw private key buffer
    const addrDetails = wallet.deriveAddress(0, 0, 0, 'taproot');
    const privateKeyBuffer = addrDetails.privateKeyBuffer;

    if (!privateKeyBuffer || privateKeyBuffer.length !== 32) {
        console.error('❌ Failed to get private key');
        process.exit(1);
    }

    try {
        await txBuilder.signAllInputs(privateKeyBuffer);
        console.log('   ✅ Schnorr signature created');
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
    console.log(`   vSize: ${txBuilder.getVirtualSize()} vB`);
    console.log(`   Hex: ${txHex.substring(0, 64)}...`);

    // Broadcast
    console.log('\n📡 Broadcasting Taproot transaction...');

    try {
        // Try mempool.space first
        const response = await fetch('https://mempool.space/testnet4/api/tx', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: txHex,
        });

        const result = await response.text();

        if (response.ok) {
            console.log('   ✅ Taproot transaction broadcast successful!');
            console.log(`   TXID: ${result}`);
            console.log(`   View: https://mempool.space/testnet4/tx/${result}`);
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
    console.log(' Done! Taproot transaction sent.');
    console.log('═'.repeat(60));
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
