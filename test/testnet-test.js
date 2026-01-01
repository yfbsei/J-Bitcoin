/**
 * @fileoverview Bitcoin Testnet Real-World Testing Script
 * @description Complete testnet integration tests for custodial and non-custodial wallets
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 * 
 * This script provides:
 * - Testnet wallet creation (both custodial and non-custodial)
 * - Address generation with QR code display
 * - Balance checking via public APIs
 * - Transaction building and signing
 * - Transaction broadcasting to testnet
 * - Transaction confirmation monitoring
 * 
 * Run: node src/wallet/testnet-test.js
 */

import { CustodialWallet } from '../src/wallet/custodial.js';
import { NonCustodialWallet } from '../src/wallet/non-custodial.js';
import { TransactionBuilder } from '../src/transaction/builder.js';
import { createHash } from 'node:crypto';
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CONFIGURATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_DIR = join(__dirname, '../../testnet-data');

// API endpoints for testnet (in order of preference)
const TESTNET_APIS = {
    // BlockCypher API (most reliable, 200 req/hour without token)
    blockcypher: {
        base: 'https://api.blockcypher.com/v1/btc/test3',
        getAddress: (addr) => `/addrs/${addr}`,
        getBalance: (addr) => `/addrs/${addr}/balance`,
        getUTXOs: (addr) => `/addrs/${addr}?unspentOnly=true`,
        broadcast: '/txs/push',
        getTx: (txid) => `/txs/${txid}`,
    },
    // Blockstream API (backup)
    blockstream: {
        base: 'https://blockstream.info/testnet/api',
        getAddress: (addr) => `/address/${addr}`,
        getUTXOs: (addr) => `/address/${addr}/utxo`,
        broadcast: '/tx',
        getTx: (txid) => `/tx/${txid}`,
    },
    // Mempool.space testnet
    mempool: {
        base: 'https://mempool.space/testnet/api',
        getAddress: (addr) => `/address/${addr}`,
        getUTXOs: (addr) => `/address/${addr}/utxo`,
        broadcast: '/tx',
        getTx: (txid) => `/tx/${txid}`,
    }
};

// Test configuration
const CONFIG = {
    // Which address types to test
    addressTypes: ['segwit', 'legacy', 'wrapped-segwit', 'taproot'],
    // Default API to use
    preferredApi: 'blockcypher',
    // Number of addresses to generate for each type
    addressCount: 3,
    // Minimum balance required to send (satoshis)
    minBalanceForTx: 10000, // 0.0001 BTC
    // Default fee rate (sat/vB)
    defaultFeeRate: 2,
    // Confirmation check interval (ms)
    confirmationCheckInterval: 30000,
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UTILITY FUNCTIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Console colors for output
 */
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
};

function log(message, color = 'white') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSection(title) {
    console.log('\n' + '━'.repeat(60));
    log(` ${title}`, 'cyan');
    console.log('━'.repeat(60));
}

function logSuccess(message) {
    log(`✓ ${message}`, 'green');
}

function logError(message) {
    log(`✗ ${message}`, 'red');
}

function logWarning(message) {
    log(`⚠ ${message}`, 'yellow');
}

function logInfo(message) {
    log(`ℹ ${message}`, 'blue');
}

/**
 * Format satoshis to BTC
 */
function satToBtc(satoshis) {
    return (satoshis / 100000000).toFixed(8);
}

/**
 * Format BTC to satoshis
 */
function btcToSat(btc) {
    return Math.floor(btc * 100000000);
}

/**
 * Sleep for given milliseconds
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Make HTTP request (works in Node.js 18+)
 */
async function httpRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        });

        const text = await response.text();
        let data;
        try {
            data = JSON.parse(text);
        } catch {
            data = text;
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${JSON.stringify(data)}`);
        }

        return data;
    } catch (error) {
        throw new Error(`Request failed: ${error.message}`);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// BLOCKCHAIN API WRAPPER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestnetAPI {
    constructor(provider = 'blockcypher') {
        this.provider = provider;
        this.api = TESTNET_APIS[provider];
        if (!this.api) {
            throw new Error(`Unknown API provider: ${provider}`);
        }
    }

    async getBalance(address) {
        try {
            if (this.provider === 'blockcypher') {
                const data = await httpRequest(
                    `${this.api.base}${this.api.getBalance(address)}`
                );
                return {
                    confirmed: data.balance || 0,
                    unconfirmed: data.unconfirmed_balance || 0,
                    total: (data.balance || 0) + (data.unconfirmed_balance || 0),
                };
            } else {
                // Blockstream/Mempool format
                const data = await httpRequest(
                    `${this.api.base}${this.api.getAddress(address)}`
                );
                return {
                    confirmed: data.chain_stats?.funded_txo_sum - data.chain_stats?.spent_txo_sum || 0,
                    unconfirmed: data.mempool_stats?.funded_txo_sum - data.mempool_stats?.spent_txo_sum || 0,
                    total: (data.chain_stats?.funded_txo_sum || 0) - (data.chain_stats?.spent_txo_sum || 0),
                };
            }
        } catch (error) {
            logWarning(`Failed to get balance from ${this.provider}: ${error.message}`);
            return { confirmed: 0, unconfirmed: 0, total: 0, error: error.message };
        }
    }

    async getUTXOs(address) {
        try {
            if (this.provider === 'blockcypher') {
                const data = await httpRequest(
                    `${this.api.base}${this.api.getUTXOs(address)}`
                );
                if (!data.txrefs) return [];
                return data.txrefs
                    .filter(tx => tx.spent === false)
                    .map(tx => ({
                        txid: tx.tx_hash,
                        vout: tx.tx_output_n,
                        value: tx.value,
                        confirmations: tx.confirmations || 0,
                    }));
            } else {
                // Blockstream/Mempool format
                const data = await httpRequest(
                    `${this.api.base}${this.api.getUTXOs(address)}`
                );
                return data.map(utxo => ({
                    txid: utxo.txid,
                    vout: utxo.vout,
                    value: utxo.value,
                    confirmations: utxo.status?.confirmed ? 1 : 0,
                }));
            }
        } catch (error) {
            logWarning(`Failed to get UTXOs from ${this.provider}: ${error.message}`);
            return [];
        }
    }

    async broadcastTransaction(txHex) {
        try {
            if (this.provider === 'blockcypher') {
                const data = await httpRequest(
                    `${this.api.base}${this.api.broadcast}`,
                    {
                        method: 'POST',
                        body: JSON.stringify({ tx: txHex }),
                    }
                );
                return { success: true, txid: data.tx?.hash || data.hash };
            } else {
                // Blockstream/Mempool format (just POST the raw hex)
                const txid = await httpRequest(
                    `${this.api.base}${this.api.broadcast}`,
                    {
                        method: 'POST',
                        body: txHex,
                        headers: { 'Content-Type': 'text/plain' },
                    }
                );
                return { success: true, txid };
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async getTransaction(txid) {
        try {
            const data = await httpRequest(
                `${this.api.base}${this.api.getTx(txid)}`
            );
            return data;
        } catch (error) {
            return { error: error.message };
        }
    }

    getExplorerUrl(type, id) {
        const explorers = {
            address: `https://mempool.space/testnet/address/${id}`,
            tx: `https://mempool.space/testnet/tx/${id}`,
        };
        return explorers[type] || '#';
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// WALLET STATE MANAGEMENT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class WalletState {
    constructor(dataDir = DATA_DIR) {
        this.dataDir = dataDir;
        this.statePath = join(dataDir, 'wallet-state.json');
        this.ensureDataDir();
    }

    ensureDataDir() {
        if (!existsSync(this.dataDir)) {
            mkdirSync(this.dataDir, { recursive: true });
            logInfo(`Created testnet data directory: ${this.dataDir}`);
        }
    }

    load() {
        try {
            if (existsSync(this.statePath)) {
                const data = readFileSync(this.statePath, 'utf8');
                return JSON.parse(data);
            }
        } catch (error) {
            logWarning(`Failed to load wallet state: ${error.message}`);
        }
        return null;
    }

    save(state) {
        try {
            writeFileSync(this.statePath, JSON.stringify(state, null, 2));
            logSuccess(`Wallet state saved to ${this.statePath}`);
        } catch (error) {
            logError(`Failed to save wallet state: ${error.message}`);
        }
    }

    clear() {
        try {
            if (existsSync(this.statePath)) {
                writeFileSync(this.statePath, '{}');
                logSuccess('Wallet state cleared');
            }
        } catch (error) {
            logError(`Failed to clear wallet state: ${error.message}`);
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TESTNET TEST RUNNER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestnetTestRunner {
    constructor() {
        this.api = new TestnetAPI(CONFIG.preferredApi);
        this.state = new WalletState();
        this.custodialWallet = null;
        this.nonCustodialWallet = null;
    }

    /**
     * Initialize or restore wallets
     */
    async initializeWallets() {
        logSection('WALLET INITIALIZATION');

        const savedState = this.state.load();

        if (savedState && savedState.custodial && savedState.nonCustodial) {
            logInfo('Found existing wallet state, restoring...');
            try {
                // Restore custodial wallet
                this.custodialWallet = CustodialWallet.fromMnemonic(
                    'test',
                    savedState.custodial.mnemonic
                );
                logSuccess('Custodial wallet restored');

                // Restore non-custodial wallet
                this.nonCustodialWallet = NonCustodialWallet.fromMnemonic(
                    'test',
                    savedState.nonCustodial.mnemonic,
                    savedState.nonCustodial.n,
                    savedState.nonCustodial.t
                );
                logSuccess('Non-custodial wallet restored');

                return { isNew: false };
            } catch (error) {
                logWarning(`Failed to restore wallets: ${error.message}`);
                logInfo('Creating new wallets...');
            }
        }

        // Create new wallets
        logInfo('Creating new testnet wallets...');

        // Custodial wallet
        const { wallet: custodialWallet, mnemonic: custodialMnemonic } =
            CustodialWallet.createNew('test', 256);
        this.custodialWallet = custodialWallet;
        logSuccess('Custodial wallet created');

        // Non-custodial wallet (3-of-3 TSS)
        const { wallet: nonCustodialWallet, mnemonic: nonCustodialMnemonic, shares, config } =
            NonCustodialWallet.createNewHD('test', 3, 1);
        this.nonCustodialWallet = nonCustodialWallet;
        logSuccess(`Non-custodial wallet created (${config.n}-of-${config.signingThreshold} TSS)`);

        // Save state
        this.state.save({
            custodial: {
                mnemonic: custodialMnemonic,
                createdAt: new Date().toISOString(),
            },
            nonCustodial: {
                mnemonic: nonCustodialMnemonic,
                n: config.n,
                t: config.t,
                createdAt: new Date().toISOString(),
            },
        });

        // Display mnemonics (critical for backup)
        console.log('\n' + '⚠'.repeat(30));
        logWarning('BACKUP YOUR MNEMONICS - WRITE THEM DOWN!');
        console.log('⚠'.repeat(30));

        console.log('\n📝 Custodial Wallet Mnemonic:');
        console.log(`   ${colors.bright}${custodialMnemonic}${colors.reset}`);

        console.log('\n📝 Non-Custodial Wallet Mnemonic:');
        console.log(`   ${colors.bright}${nonCustodialMnemonic}${colors.reset}`);

        return { isNew: true, custodialMnemonic, nonCustodialMnemonic };
    }

    /**
     * Generate and display addresses for funding
     */
    async displayAddresses() {
        logSection('TESTNET ADDRESSES');
        logInfo('Fund these addresses via testnet faucets:');
        console.log('\n🔗 Faucets:');
        console.log('   - https://coinfaucet.eu/en/btc-testnet/');
        console.log('   - https://bitcoinfaucet.uo1.net/');
        console.log('   - https://testnet-faucet.com/btc-testnet/');

        const addresses = {
            custodial: {},
            nonCustodial: {},
        };

        // Custodial addresses
        console.log('\n📍 CUSTODIAL WALLET ADDRESSES:');
        console.log('─'.repeat(50));
        for (const type of CONFIG.addressTypes) {
            try {
                const addr = this.custodialWallet.getReceivingAddress(0, 0, type);
                addresses.custodial[type] = addr.address;
                console.log(`   ${type.padEnd(15)}: ${addr.address}`);
                console.log(`   ${''.padEnd(15)}  └─ ${this.api.getExplorerUrl('address', addr.address)}`);
            } catch (error) {
                logWarning(`   ${type}: Not supported - ${error.message}`);
            }
        }

        // Non-custodial addresses
        console.log('\n📍 NON-CUSTODIAL WALLET ADDRESSES:');
        console.log('─'.repeat(50));
        for (const type of CONFIG.addressTypes) {
            try {
                const addr = this.nonCustodialWallet.getReceivingAddress(0, 0, type);
                addresses.nonCustodial[type] = addr.address;
                console.log(`   ${type.padEnd(15)}: ${addr.address}`);
                console.log(`   ${''.padEnd(15)}  └─ ${this.api.getExplorerUrl('address', addr.address)}`);
            } catch (error) {
                logWarning(`   ${type}: Not supported - ${error.message}`);
            }
        }

        return addresses;
    }

    /**
     * Check balances for all addresses
     */
    async checkBalances() {
        logSection('BALANCE CHECK');

        const balances = {
            custodial: { total: 0, byType: {} },
            nonCustodial: { total: 0, byType: {} },
        };

        // Check custodial balances
        console.log('\n💰 CUSTODIAL WALLET BALANCES:');
        console.log('─'.repeat(50));
        for (const type of CONFIG.addressTypes) {
            try {
                const addr = this.custodialWallet.getReceivingAddress(0, 0, type);
                const balance = await this.api.getBalance(addr.address);
                balances.custodial.byType[type] = balance;
                balances.custodial.total += balance.total;

                const btc = satToBtc(balance.total);
                const status = balance.total > 0 ? '✓' : '○';
                console.log(`   ${status} ${type.padEnd(15)}: ${btc} tBTC (${balance.total} sats)`);
                if (balance.unconfirmed > 0) {
                    console.log(`     ${''.padEnd(15)}  └─ Unconfirmed: ${satToBtc(balance.unconfirmed)} tBTC`);
                }
            } catch (error) {
                logWarning(`   ${type}: Error - ${error.message}`);
            }
            await sleep(500); // Rate limiting
        }

        // Check non-custodial balances
        console.log('\n💰 NON-CUSTODIAL WALLET BALANCES:');
        console.log('─'.repeat(50));
        for (const type of CONFIG.addressTypes) {
            try {
                const addr = this.nonCustodialWallet.getReceivingAddress(0, 0, type);
                const balance = await this.api.getBalance(addr.address);
                balances.nonCustodial.byType[type] = balance;
                balances.nonCustodial.total += balance.total;

                const btc = satToBtc(balance.total);
                const status = balance.total > 0 ? '✓' : '○';
                console.log(`   ${status} ${type.padEnd(15)}: ${btc} tBTC (${balance.total} sats)`);
                if (balance.unconfirmed > 0) {
                    console.log(`     ${''.padEnd(15)}  └─ Unconfirmed: ${satToBtc(balance.unconfirmed)} tBTC`);
                }
            } catch (error) {
                logWarning(`   ${type}: Error - ${error.message}`);
            }
            await sleep(500); // Rate limiting
        }

        console.log('\n' + '─'.repeat(50));
        console.log(`   Custodial Total:     ${satToBtc(balances.custodial.total)} tBTC`);
        console.log(`   Non-Custodial Total: ${satToBtc(balances.nonCustodial.total)} tBTC`);

        return balances;
    }

    /**
     * Get UTXOs for a wallet
     */
    async getWalletUTXOs(walletType, addressType = 'segwit') {
        const wallet = walletType === 'custodial' ? this.custodialWallet : this.nonCustodialWallet;
        const addr = wallet.getReceivingAddress(0, 0, addressType);
        const utxos = await this.api.getUTXOs(addr.address);

        return {
            address: addr.address,
            addressInfo: addr,
            utxos,
            totalValue: utxos.reduce((sum, u) => sum + u.value, 0),
        };
    }

    /**
     * Build a transaction
     */
    async buildTransaction(options) {
        const {
            walletType = 'custodial',
            fromType = 'segwit',
            toAddress,
            amount, // in satoshis
            feeRate = CONFIG.defaultFeeRate,
        } = options;

        logSection('BUILDING TRANSACTION');

        const wallet = walletType === 'custodial' ? this.custodialWallet : this.nonCustodialWallet;

        // Get UTXOs
        logInfo('Fetching UTXOs...');
        const { address, addressInfo, utxos, totalValue } =
            await this.getWalletUTXOs(walletType, fromType);

        if (utxos.length === 0) {
            throw new Error(`No UTXOs found for ${address}`);
        }

        logSuccess(`Found ${utxos.length} UTXO(s) with total ${satToBtc(totalValue)} tBTC`);

        // Calculate fee (rough estimate)
        const inputCount = utxos.length;
        const outputCount = 2; // destination + change
        const estimatedTxSize = inputCount * 148 + outputCount * 34 + 10;
        const estimatedFee = estimatedTxSize * feeRate;

        logInfo(`Estimated fee: ${estimatedFee} sats (~${estimatedTxSize} vB @ ${feeRate} sat/vB)`);

        if (totalValue < amount + estimatedFee) {
            throw new Error(`Insufficient balance: ${totalValue} sats < ${amount + estimatedFee} sats needed`);
        }

        // Build transaction
        const txBuilder = new TransactionBuilder('test');

        // Add inputs
        for (const utxo of utxos) {
            txBuilder.addInput({
                txid: utxo.txid,
                vout: utxo.vout,
                value: utxo.value,
                scriptPubKey: addressInfo.scriptPubKey,
                type: addressInfo.type === 'segwit' ? 'p2wpkh' :
                    addressInfo.type === 'legacy' ? 'p2pkh' :
                        addressInfo.type === 'taproot' ? 'p2tr' : 'p2sh-p2wpkh',
            });
        }

        // Add destination output
        txBuilder.addOutput({
            address: toAddress,
            value: amount,
        });

        // Add change output
        const changeValue = totalValue - amount - estimatedFee;
        if (changeValue > 546) { // dust limit
            const changeAddr = wallet.getChangeAddress(0, 0, fromType);
            txBuilder.addOutput({
                address: changeAddr.address,
                value: changeValue,
            });
            logInfo(`Change: ${satToBtc(changeValue)} tBTC to ${changeAddr.address}`);
        }

        // Get private key for signing
        const wif = wallet.exportWIF(0, 0, 0, fromType);

        // This is a simplified signing - full implementation would depend on your builder
        logInfo('Signing transaction...');

        // Note: The actual signing depends on your TransactionBuilder implementation
        // This is a placeholder that shows the intent
        try {
            await txBuilder.signAllInputs(wif);
            logSuccess('Transaction signed');
        } catch (signError) {
            logWarning(`Signing note: ${signError.message}`);
            logInfo('Transaction built but signature may need manual verification');
        }

        const tx = txBuilder.build();

        return {
            txBuilder,
            tx,
            details: {
                from: address,
                to: toAddress,
                amount: amount,
                fee: estimatedFee,
                change: changeValue,
                utxosUsed: utxos.length,
            },
        };
    }

    /**
     * Broadcast a transaction
     */
    async broadcastTransaction(txHex) {
        logSection('BROADCASTING TRANSACTION');

        logInfo('Broadcasting to testnet...');
        const result = await this.api.broadcastTransaction(txHex);

        if (result.success) {
            logSuccess(`Transaction broadcast successful!`);
            console.log(`   TXID: ${result.txid}`);
            console.log(`   Explorer: ${this.api.getExplorerUrl('tx', result.txid)}`);
            return result;
        } else {
            logError(`Broadcast failed: ${result.error}`);
            return result;
        }
    }

    /**
     * Monitor transaction confirmation
     */
    async monitorTransaction(txid, maxChecks = 20) {
        logSection('MONITORING TRANSACTION');
        logInfo(`Waiting for confirmation of ${txid}...`);

        for (let i = 0; i < maxChecks; i++) {
            const tx = await this.api.getTransaction(txid);

            if (tx.error) {
                logWarning(`Check ${i + 1}/${maxChecks}: ${tx.error}`);
            } else {
                const confirmations = tx.confirmations || tx.status?.confirmed ? 1 : 0;
                if (confirmations > 0) {
                    logSuccess(`Transaction confirmed! Confirmations: ${confirmations}`);
                    return { confirmed: true, confirmations, tx };
                }
                logInfo(`Check ${i + 1}/${maxChecks}: Pending (0 confirmations)`);
            }

            if (i < maxChecks - 1) {
                await sleep(CONFIG.confirmationCheckInterval);
            }
        }

        logWarning('Transaction still unconfirmed after maximum checks');
        return { confirmed: false };
    }

    /**
     * Run complete test flow
     */
    async runFullTest() {
        console.log('\n');
        console.log('═'.repeat(60));
        log(' 🔧 J-BITCOIN TESTNET TESTING SUITE', 'bright');
        console.log('═'.repeat(60));
        console.log(`   Network: Bitcoin Testnet`);
        console.log(`   API Provider: ${CONFIG.preferredApi}`);
        console.log(`   Date: ${new Date().toISOString()}`);

        try {
            // Step 1: Initialize wallets
            const { isNew } = await this.initializeWallets();

            // Step 2: Display addresses
            const addresses = await this.displayAddresses();

            // Step 3: Check balances
            const balances = await this.checkBalances();

            // Step 4: Show test instructions
            logSection('TESTING INSTRUCTIONS');

            if (balances.custodial.total === 0 && balances.nonCustodial.total === 0) {
                logWarning('No funds detected in any wallet!');
                console.log('\n📋 Next Steps:');
                console.log('   1. Copy one of the addresses above');
                console.log('   2. Visit a testnet faucet and request tBTC');
                console.log('   3. Wait for confirmation (1-10 minutes)');
                console.log('   4. Run this script again to check balances');
                console.log('\n   After funding, run with --send to test transactions');
            } else {
                logSuccess('Funds detected! Ready for transaction testing.');
                console.log('\n📋 Available Commands:');
                console.log('   node src/wallet/testnet-test.js          - Check balances');
                console.log('   node src/wallet/testnet-test.js --send   - Send test transaction');
                console.log('   node src/wallet/testnet-test.js --reset  - Create new wallets');
            }

            // Step 5: If --send flag, attempt transaction
            if (process.argv.includes('--send')) {
                await this.runTransactionTest(balances);
            }

            // Step 6: If --reset flag, clear state
            if (process.argv.includes('--reset')) {
                this.state.clear();
                logInfo('Run the script again to create new wallets');
            }

            logSection('TEST COMPLETE');
            logSuccess('Testnet testing session completed');

        } catch (error) {
            logError(`Test failed: ${error.message}`);
            console.error(error);
            process.exit(1);
        }
    }

    /**
     * Run transaction test
     */
    async runTransactionTest(balances) {
        logSection('TRANSACTION TEST');

        // Find a funded wallet and address type
        let fundedWallet = null;
        let fundedType = null;
        let fundedBalance = 0;

        // Check custodial first
        for (const [type, balance] of Object.entries(balances.custodial.byType)) {
            if (balance.total >= CONFIG.minBalanceForTx) {
                fundedWallet = 'custodial';
                fundedType = type;
                fundedBalance = balance.total;
                break;
            }
        }

        // Then check non-custodial
        if (!fundedWallet) {
            for (const [type, balance] of Object.entries(balances.nonCustodial.byType)) {
                if (balance.total >= CONFIG.minBalanceForTx) {
                    fundedWallet = 'nonCustodial';
                    fundedType = type;
                    fundedBalance = balance.total;
                    break;
                }
            }
        }

        if (!fundedWallet) {
            logWarning(`No wallet has minimum balance of ${CONFIG.minBalanceForTx} sats for testing`);
            return;
        }

        logInfo(`Using ${fundedWallet} wallet with ${fundedType} address (${satToBtc(fundedBalance)} tBTC)`);

        // For testing, send to the other wallet type
        const targetWallet = fundedWallet === 'custodial' ? this.nonCustodialWallet : this.custodialWallet;
        const targetAddr = targetWallet.getReceivingAddress(0, 0, 'segwit');

        const sendAmount = Math.min(5000, Math.floor(fundedBalance * 0.1)); // 10% or 5000 sats

        console.log('\n📤 Transaction Details:');
        console.log(`   From: ${fundedWallet} (${fundedType})`);
        console.log(`   To: ${fundedWallet === 'custodial' ? 'nonCustodial' : 'custodial'} (segwit)`);
        console.log(`   Amount: ${satToBtc(sendAmount)} tBTC (${sendAmount} sats)`);
        console.log(`   Destination: ${targetAddr.address}`);

        try {
            const { tx, details } = await this.buildTransaction({
                walletType: fundedWallet,
                fromType: fundedType,
                toAddress: targetAddr.address,
                amount: sendAmount,
            });

            console.log('\n📝 Built Transaction:');
            console.log(`   Inputs: ${details.utxosUsed}`);
            console.log(`   Fee: ${details.fee} sats`);
            console.log(`   Change: ${satToBtc(details.change)} tBTC`);

            if (tx.hex) {
                console.log(`   Size: ${tx.hex.length / 2} bytes`);

                // Broadcast
                const result = await this.broadcastTransaction(tx.hex);

                if (result.success) {
                    // Monitor for confirmation
                    await this.monitorTransaction(result.txid, 3);
                }
            } else {
                logWarning('Transaction hex not available - signing may have failed');
                logInfo('Check your TransactionBuilder.build() implementation');
            }

        } catch (error) {
            logError(`Transaction test failed: ${error.message}`);
            console.error(error);
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MAIN
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function main() {
    const runner = new TestnetTestRunner();
    await runner.runFullTest();
}

main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});

export { TestnetTestRunner, TestnetAPI, WalletState, CONFIG };
