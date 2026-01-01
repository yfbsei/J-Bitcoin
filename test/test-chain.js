/**
 * @fileoverview Chain Transaction Test - All Address Types
 * @description Tests Legacy (P2PKH) and Wrapped SegWit (P2SH-P2WPKH) for both wallets
 * 
 * Chain: TSS SegWit → Legacy → Wrapped SegWit → Faucet
 * 
 * Run: node src/wallet/test-chain.js
 */

import { CustodialWallet } from '../src/wallet/custodial.js';
import { NonCustodialWallet } from '../src/wallet/non-custodial.js';
import { TransactionBuilder } from '../src/transaction/builder.js';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration
const FAUCET_ADDRESS = 'tb1qn9rvr53m7qvrpysx48svuxsgahs88xfsskx367';
const FEE_RATE = 2; // sat/vB
const API_BASE = 'https://mempool.space/testnet4/api';

// State file to track chain progress
const CHAIN_STATE_FILE = join(__dirname, './testnet-data/chain-state.json');

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

async function broadcast(txHex) {
    const response = await fetch(`${API_BASE}/tx`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: txHex,
    });
    const result = await response.text();
    return { success: response.ok, txid: response.ok ? result : null, error: response.ok ? null : result };
}

async function getUtxos(address) {
    return await httpRequest(`${API_BASE}/address/${address}/utxo`);
}

async function waitForConfirmation(txid, maxWait = 60) {
    console.log(`   Waiting for confirmation (max ${maxWait}s)...`);
    for (let i = 0; i < maxWait; i += 10) {
        await new Promise(r => setTimeout(r, 10000));
        const tx = await httpRequest(`${API_BASE}/tx/${txid}`);
        if (tx.status?.confirmed) {
            console.log('   ✅ Confirmed!');
            return true;
        }
        console.log(`   ... still pending (${i + 10}s)`);
    }
    return false;
}

function log(msg, type = 'info') {
    const prefix = type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warn' ? '⚠️' : '📍';
    console.log(`${prefix} ${msg}`);
}

async function buildAndBroadcast(wallet, fromAddr, toAddress, amount, addressType) {
    const txBuilder = new TransactionBuilder('test');

    // Get UTXOs
    const utxos = await getUtxos(fromAddr.address);
    if (!utxos || utxos.length === 0) {
        throw new Error(`No UTXOs found for ${fromAddr.address}`);
    }

    let totalIn = 0;
    for (const utxo of utxos) {
        const inputType = addressType === 'legacy' ? 'p2pkh' :
            addressType === 'wrapped-segwit' ? 'p2sh-p2wpkh' :
                addressType === 'taproot' ? 'p2tr' : 'p2wpkh';

        txBuilder.addInput({
            txid: utxo.txid,
            vout: utxo.vout,
            value: utxo.value,
            scriptPubKey: fromAddr.scriptPubKey,
            redeemScript: fromAddr.redeemScript,
            type: inputType,
        });
        totalIn += utxo.value;
    }

    // Calculate fee based on address types
    const inputVSize = addressType === 'legacy' ? 148 :
        addressType === 'wrapped-segwit' ? 91 :
            addressType === 'taproot' ? 58 : 68;
    const outputVSize = toAddress.startsWith('tb1p') ? 43 :
        toAddress.startsWith('tb1q') ? 31 :
            toAddress.startsWith('2') ? 32 : 34;
    const fee = (inputVSize + outputVSize + 10) * FEE_RATE;
    const sendAmount = amount || (totalIn - fee);

    if (sendAmount <= 546) {
        throw new Error(`Amount too small: ${sendAmount} sats`);
    }

    txBuilder.addOutput({
        address: toAddress,
        value: sendAmount,
    });

    // Sign
    await txBuilder.signAllInputs(fromAddr.privateKeyBuffer);

    const txHex = txBuilder.toHex();
    console.log(`   Built tx: ${txHex.substring(0, 40)}... (${txHex.length / 2} bytes)`);

    // Broadcast
    const result = await broadcast(txHex);
    if (!result.success) {
        throw new Error(`Broadcast failed: ${result.error}`);
    }

    return { txid: result.txid, amount: sendAmount, fee };
}

async function main() {
    console.log('═'.repeat(60));
    console.log(' 🔗 CHAIN TRANSACTION TEST - ALL ADDRESS TYPES');
    console.log('═'.repeat(60));
    console.log(' Testing: Legacy (P2PKH) & Wrapped SegWit (P2SH-P2WPKH)');
    console.log(' Wallets: Custodial & Non-Custodial');
    console.log('═'.repeat(60));

    // Load wallet state
    const statePath = join(__dirname, './testnet-data/wallet-state.json');
    if (!existsSync(statePath)) {
        console.error('❌ No wallet state found. Run testnet-test.js first.');
        process.exit(1);
    }

    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    const custodial = CustodialWallet.fromMnemonic('test', state.custodial.mnemonic);
    const nonCustodial = NonCustodialWallet.fromMnemonic(
        'test', state.nonCustodial.mnemonic, state.nonCustodial.n, state.nonCustodial.t
    );

    // Get all addresses
    const addresses = {
        tssSegwit: nonCustodial.getReceivingAddress(0, 0, 'segwit'),
        custodialLegacy: custodial.getReceivingAddress(0, 0, 'legacy'),
        custodialWrapped: custodial.getReceivingAddress(0, 0, 'wrapped-segwit'),
        ncLegacy: nonCustodial.getReceivingAddress(0, 0, 'legacy'),
        ncWrapped: nonCustodial.getReceivingAddress(0, 0, 'wrapped-segwit'),
    };

    console.log('\n📋 Address Chain:');
    console.log(`   1. TSS SegWit: ${addresses.tssSegwit.address}`);
    console.log(`   2. Custodial Legacy: ${addresses.custodialLegacy.address}`);
    console.log(`   3. Custodial Wrapped: ${addresses.custodialWrapped.address}`);
    console.log(`   4. NC Legacy: ${addresses.ncLegacy.address}`);
    console.log(`   5. NC Wrapped: ${addresses.ncWrapped.address}`);
    console.log(`   6. Faucet: ${FAUCET_ADDRESS}`);

    // Check current balance
    const utxos = await getUtxos(addresses.tssSegwit.address);
    if (!utxos || utxos.length === 0) {
        log('No funds in TSS SegWit wallet. Fund it first.', 'error');
        process.exit(1);
    }

    const totalBalance = utxos.reduce((sum, u) => sum + u.value, 0);
    console.log(`\n💰 Starting balance: ${totalBalance} sats`);

    // Check if UTXOs are confirmed
    for (const utxo of utxos) {
        const tx = await httpRequest(`${API_BASE}/tx/${utxo.txid}`);
        if (!tx.status?.confirmed) {
            log(`UTXO ${utxo.txid.substring(0, 8)}... not confirmed yet. Wait and retry.`, 'warn');
            process.exit(0);
        }
    }

    const results = [];

    // ═══════════════════════════════════════════════════════════════
    // STEP 1: TSS SegWit → Split to Custodial Legacy + NC Legacy
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 1: TSS SegWit → Custodial Legacy + NC Legacy');
    console.log('─'.repeat(50));

    try {
        const txBuilder = new TransactionBuilder('test');

        // Add all UTXOs as inputs
        let totalIn = 0;
        for (const utxo of utxos) {
            txBuilder.addInput({
                txid: utxo.txid,
                vout: utxo.vout,
                value: utxo.value,
                scriptPubKey: addresses.tssSegwit.scriptPubKey,
                type: 'p2wpkh',
            });
            totalIn += utxo.value;
        }

        // Split into two outputs (minus fees)
        const fee = 200; // Estimate for 1 input, 2 outputs
        const halfAmount = Math.floor((totalIn - fee) / 2);

        txBuilder.addOutput({ address: addresses.custodialLegacy.address, value: halfAmount });
        txBuilder.addOutput({ address: addresses.ncLegacy.address, value: halfAmount });

        await txBuilder.signAllInputs(addresses.tssSegwit.privateKeyBuffer);
        const txHex = txBuilder.toHex();

        const result = await broadcast(txHex);
        if (result.success) {
            log(`Split tx broadcast: ${result.txid}`, 'success');
            log(`   Custodial Legacy: ${halfAmount} sats`);
            log(`   NC Legacy: ${halfAmount} sats`);
            results.push({ step: 1, txid: result.txid, type: 'split', amounts: [halfAmount, halfAmount] });

            // Wait for confirmation before next step
            console.log('\n⏳ Waiting for confirmation before next step...');
            const confirmed = await waitForConfirmation(result.txid, 120);
            if (!confirmed) {
                log('Transaction not confirmed yet. Run script again later.', 'warn');
                writeFileSync(CHAIN_STATE_FILE, JSON.stringify({ step: 1, results }, null, 2));
                process.exit(0);
            }
        } else {
            throw new Error(result.error);
        }
    } catch (e) {
        log(`Step 1 failed: ${e.message}`, 'error');
        process.exit(1);
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 2: Custodial Legacy → Custodial Wrapped SegWit
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 2: Custodial Legacy (P2PKH) → Custodial Wrapped (P2SH-P2WPKH)');
    console.log('─'.repeat(50));

    try {
        const result = await buildAndBroadcast(
            custodial,
            addresses.custodialLegacy,
            addresses.custodialWrapped.address,
            null, // Use full balance
            'legacy'
        );
        log(`Legacy → Wrapped: ${result.txid}`, 'success');
        log(`   Amount: ${result.amount} sats, Fee: ${result.fee} sats`);
        results.push({ step: 2, txid: result.txid, type: 'custodial-legacy-to-wrapped', amount: result.amount });

        await waitForConfirmation(result.txid, 120);
    } catch (e) {
        log(`Step 2 failed: ${e.message}`, 'error');
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 3: NC Legacy → NC Wrapped SegWit
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 3: NC Legacy (P2PKH) → NC Wrapped (P2SH-P2WPKH)');
    console.log('─'.repeat(50));

    try {
        const result = await buildAndBroadcast(
            nonCustodial,
            addresses.ncLegacy,
            addresses.ncWrapped.address,
            null,
            'legacy'
        );
        log(`NC Legacy → Wrapped: ${result.txid}`, 'success');
        log(`   Amount: ${result.amount} sats, Fee: ${result.fee} sats`);
        results.push({ step: 3, txid: result.txid, type: 'nc-legacy-to-wrapped', amount: result.amount });

        await waitForConfirmation(result.txid, 120);
    } catch (e) {
        log(`Step 3 failed: ${e.message}`, 'error');
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 4: Custodial Wrapped → Faucet
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 4: Custodial Wrapped (P2SH-P2WPKH) → Faucet');
    console.log('─'.repeat(50));

    try {
        const result = await buildAndBroadcast(
            custodial,
            addresses.custodialWrapped,
            FAUCET_ADDRESS,
            null,
            'wrapped-segwit'
        );
        log(`Wrapped → Faucet: ${result.txid}`, 'success');
        log(`   Amount: ${result.amount} sats, Fee: ${result.fee} sats`);
        results.push({ step: 4, txid: result.txid, type: 'custodial-wrapped-to-faucet', amount: result.amount });
    } catch (e) {
        log(`Step 4 failed: ${e.message}`, 'error');
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 5: NC Wrapped → Faucet
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 5: NC Wrapped (P2SH-P2WPKH) → Faucet');
    console.log('─'.repeat(50));

    try {
        const result = await buildAndBroadcast(
            nonCustodial,
            addresses.ncWrapped,
            FAUCET_ADDRESS,
            null,
            'wrapped-segwit'
        );
        log(`NC Wrapped → Faucet: ${result.txid}`, 'success');
        log(`   Amount: ${result.amount} sats, Fee: ${result.fee} sats`);
        results.push({ step: 5, txid: result.txid, type: 'nc-wrapped-to-faucet', amount: result.amount });
    } catch (e) {
        log(`Step 5 failed: ${e.message}`, 'error');
    }

    // ═══════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '═'.repeat(60));
    console.log(' CHAIN TEST RESULTS');
    console.log('═'.repeat(60));

    for (const r of results) {
        console.log(`Step ${r.step}: ${r.type}`);
        console.log(`   TXID: ${r.txid}`);
        console.log(`   View: ${API_BASE.replace('/api', '')}/tx/${r.txid}`);
    }

    console.log('\n' + '═'.repeat(60));
    console.log(' ✅ Chain test complete!');
    console.log('═'.repeat(60));
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
