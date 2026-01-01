/**
 * @fileoverview Continue Chain Test from Step 2
 * @description Tests Legacy (P2PKH) and Wrapped SegWit (P2SH-P2WPKH) signing
 * 
 * Run: node src/wallet/test-chain-continue.js
 */

import { CustodialWallet } from '../src/wallet/custodial.js';
import { NonCustodialWallet } from '../src/wallet/non-custodial.js';
import { TransactionBuilder } from '../src/transaction/builder.js';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const FAUCET_ADDRESS = 'tb1qn9rvr53m7qvrpysx48svuxsgahs88xfsskx367';
const FEE_RATE = 2;
const API_BASE = 'https://mempool.space/testnet4/api';

async function httpRequest(url) {
    const response = await fetch(url);
    const text = await response.text();
    try { return JSON.parse(text); } catch { return text; }
}

async function broadcast(txHex) {
    const response = await fetch(`${API_BASE}/tx`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: txHex,
    });
    const result = await response.text();
    return { success: response.ok, txid: result, error: response.ok ? null : result };
}

async function getUtxos(address) {
    return await httpRequest(`${API_BASE}/address/${address}/utxo`);
}

async function waitForConfirmation(txid, maxWait = 120) {
    console.log(`   ⏳ Waiting for confirmation...`);
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

async function signAndBroadcast(wallet, fromAddr, toAddress, addressType) {
    const utxos = await getUtxos(fromAddr.address);
    if (!utxos || utxos.length === 0) {
        throw new Error(`No UTXOs for ${fromAddr.address}`);
    }

    const txBuilder = new TransactionBuilder('test');

    let totalIn = 0;
    for (const utxo of utxos) {
        const inputType = addressType === 'legacy' ? 'p2pkh' :
            addressType === 'wrapped-segwit' ? 'p2sh-p2wpkh' : 'p2wpkh';

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

    // Fee calculation
    const inputVSize = addressType === 'legacy' ? 148 :
        addressType === 'wrapped-segwit' ? 91 : 68;
    const outputVSize = toAddress.startsWith('tb1p') ? 43 :
        toAddress.startsWith('tb1q') ? 31 :
            toAddress.startsWith('2') ? 32 : 34;
    const fee = (inputVSize + outputVSize + 10) * FEE_RATE;
    const sendAmount = totalIn - fee;

    if (sendAmount <= 546) throw new Error(`Dust: ${sendAmount}`);

    txBuilder.addOutput({ address: toAddress, value: sendAmount });

    await txBuilder.signAllInputs(fromAddr.privateKeyBuffer);
    const txHex = txBuilder.toHex();

    console.log(`   Built: ${txHex.length / 2} bytes, sending ${sendAmount} sats`);

    const result = await broadcast(txHex);
    if (!result.success) throw new Error(result.error);

    return { txid: result.txid, amount: sendAmount, fee };
}

async function main() {
    console.log('═'.repeat(60));
    console.log(' 🔗 CHAIN TEST CONTINUATION - Steps 2-5');
    console.log('═'.repeat(60));

    const statePath = join(__dirname, './testnet-data/wallet-state.json');
    const state = JSON.parse(readFileSync(statePath, 'utf8'));

    const custodial = CustodialWallet.fromMnemonic('test', state.custodial.mnemonic);
    const nonCustodial = NonCustodialWallet.fromMnemonic(
        'test', state.nonCustodial.mnemonic, state.nonCustodial.n, state.nonCustodial.t
    );

    const custodialLegacy = custodial.getReceivingAddress(0, 0, 'legacy');
    const custodialWrapped = custodial.getReceivingAddress(0, 0, 'wrapped-segwit');
    const ncLegacy = nonCustodial.getReceivingAddress(0, 0, 'legacy');
    const ncWrapped = nonCustodial.getReceivingAddress(0, 0, 'wrapped-segwit');

    const results = [];

    // ═══════════════════════════════════════════════════════════════
    // STEP 2: Custodial Legacy → Custodial Wrapped
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 2: Custodial Legacy (P2PKH) → Wrapped (P2SH-P2WPKH)');
    console.log('─'.repeat(50));

    try {
        const utxos = await getUtxos(custodialLegacy.address);
        if (utxos && utxos.length > 0) {
            const result = await signAndBroadcast(custodial, custodialLegacy, custodialWrapped.address, 'legacy');
            console.log(`✅ TXID: ${result.txid}`);
            console.log(`   View: ${API_BASE.replace('/api', '')}/tx/${result.txid}`);
            results.push({ step: 2, txid: result.txid, amount: result.amount });
            await waitForConfirmation(result.txid);
        } else {
            console.log('⚠️ No funds in Custodial Legacy, skipping...');
        }
    } catch (e) {
        console.log(`❌ Step 2 failed: ${e.message}`);
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 3: NC Legacy → NC Wrapped
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 3: NC Legacy (P2PKH) → NC Wrapped (P2SH-P2WPKH)');
    console.log('─'.repeat(50));

    try {
        const utxos = await getUtxos(ncLegacy.address);
        if (utxos && utxos.length > 0) {
            const result = await signAndBroadcast(nonCustodial, ncLegacy, ncWrapped.address, 'legacy');
            console.log(`✅ TXID: ${result.txid}`);
            console.log(`   View: ${API_BASE.replace('/api', '')}/tx/${result.txid}`);
            results.push({ step: 3, txid: result.txid, amount: result.amount });
            await waitForConfirmation(result.txid);
        } else {
            console.log('⚠️ No funds in NC Legacy, skipping...');
        }
    } catch (e) {
        console.log(`❌ Step 3 failed: ${e.message}`);
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 4: Custodial Wrapped → Faucet
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 4: Custodial Wrapped (P2SH-P2WPKH) → Faucet');
    console.log('─'.repeat(50));

    try {
        const utxos = await getUtxos(custodialWrapped.address);
        if (utxos && utxos.length > 0) {
            const result = await signAndBroadcast(custodial, custodialWrapped, FAUCET_ADDRESS, 'wrapped-segwit');
            console.log(`✅ TXID: ${result.txid}`);
            console.log(`   View: ${API_BASE.replace('/api', '')}/tx/${result.txid}`);
            results.push({ step: 4, txid: result.txid, amount: result.amount });
        } else {
            console.log('⚠️ No funds in Custodial Wrapped, skipping...');
        }
    } catch (e) {
        console.log(`❌ Step 4 failed: ${e.message}`);
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 5: NC Wrapped → Faucet
    // ═══════════════════════════════════════════════════════════════
    console.log('\n' + '─'.repeat(50));
    console.log('STEP 5: NC Wrapped (P2SH-P2WPKH) → Faucet');
    console.log('─'.repeat(50));

    try {
        const utxos = await getUtxos(ncWrapped.address);
        if (utxos && utxos.length > 0) {
            const result = await signAndBroadcast(nonCustodial, ncWrapped, FAUCET_ADDRESS, 'wrapped-segwit');
            console.log(`✅ TXID: ${result.txid}`);
            console.log(`   View: ${API_BASE.replace('/api', '')}/tx/${result.txid}`);
            results.push({ step: 5, txid: result.txid, amount: result.amount });
        } else {
            console.log('⚠️ No funds in NC Wrapped, skipping...');
        }
    } catch (e) {
        console.log(`❌ Step 5 failed: ${e.message}`);
    }

    // Summary
    console.log('\n' + '═'.repeat(60));
    console.log(' CHAIN TEST RESULTS');
    console.log('═'.repeat(60));

    for (const r of results) {
        console.log(`✅ Step ${r.step}: ${r.txid.substring(0, 16)}... (${r.amount} sats)`);
    }

    console.log('\n🏆 Address types tested:');
    if (results.some(r => r.step === 2)) console.log('   ✅ Custodial Legacy (P2PKH) signing');
    if (results.some(r => r.step === 3)) console.log('   ✅ Non-Custodial Legacy (P2PKH) signing');
    if (results.some(r => r.step === 4)) console.log('   ✅ Custodial Wrapped SegWit (P2SH-P2WPKH) signing');
    if (results.some(r => r.step === 5)) console.log('   ✅ Non-Custodial Wrapped SegWit (P2SH-P2WPKH) signing');
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
