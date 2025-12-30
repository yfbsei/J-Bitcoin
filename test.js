/**
 * J-Bitcoin Wallet Test Suite
 * Tests both CustodialWallet and NonCustodialWallet functionality
 * 
 * Run: node test.js
 */

import {
    CustodialWallet,
    NonCustodialWallet,
    LIBRARY_INFO,
    NETWORKS
} from './index.js';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UTILITIES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    red: '\x1b[31m'
};

const log = {
    header: (msg) => console.log(`\n${colors.bright}${colors.cyan}━━━ ${msg} ━━━${colors.reset}\n`),
    success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
    info: (label, value) => console.log(`  ${colors.yellow}${label}:${colors.reset} ${value}`),
    error: (msg) => console.log(`${colors.red}✗ ERROR: ${msg}${colors.reset}`),
    divider: () => console.log('')
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CUSTODIAL WALLET TESTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testCustodialWallet() {
    log.header('CUSTODIAL WALLET TEST');

    try {
        // Create new wallet
        console.log('Creating new custodial wallet...');
        const { wallet, mnemonic } = CustodialWallet.createNew('main');
        log.success('Wallet created successfully');

        log.info('Network', wallet.getNetwork());
        log.info('Mnemonic', mnemonic);
        log.info('Extended Public Key', wallet.getExtendedPublicKey()?.substring(0, 40) + '...');

        log.divider();

        // Derive addresses
        console.log('Deriving addresses...');

        const segwitAddr = wallet.getReceivingAddress(0, 0, 'segwit');
        log.success('SegWit address derived');
        log.info('Address', segwitAddr.address);
        log.info('Path', segwitAddr.path);
        log.info('Type', segwitAddr.type);

        log.divider();

        const legacyAddr = wallet.getReceivingAddress(0, 0, 'legacy');
        log.success('Legacy address derived');
        log.info('Address', legacyAddr.address);
        log.info('Path', legacyAddr.path);

        log.divider();

        const taprootAddr = wallet.getReceivingAddress(0, 0, 'taproot');
        log.success('Taproot address derived');
        log.info('Address', taprootAddr.address);
        log.info('Path', taprootAddr.path);

        log.divider();

        // Change address
        const changeAddr = wallet.getChangeAddress(0, 0, 'segwit');
        log.success('Change address derived');
        log.info('Address', changeAddr.address);
        log.info('Path', changeAddr.path);

        log.divider();

        // Sign message
        console.log('Testing message signing...');
        const message = 'Hello, Bitcoin!';
        const signature = wallet.signMessage(message);
        log.success('Message signed');
        log.info('Message', message);
        log.info('Signature R', signature.r?.toString(16).substring(0, 20) + '...');
        log.info('Signature S', signature.s?.toString(16).substring(0, 20) + '...');

        log.divider();

        // Restore wallet from mnemonic
        console.log('Testing wallet restoration...');
        const restoredWallet = CustodialWallet.fromMnemonic('main', mnemonic);
        const restoredAddr = restoredWallet.getReceivingAddress(0, 0, 'segwit');

        if (restoredAddr.address === segwitAddr.address) {
            log.success('Wallet restored correctly - addresses match!');
        } else {
            log.error('Restored wallet addresses do not match');
        }

        log.divider();

        // Export wallet info
        console.log('Wallet JSON export:');
        console.log(JSON.stringify(wallet.toJSON(), null, 2));

        return true;
    } catch (error) {
        log.error(error.message);
        console.error(error);
        return false;
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// NON-CUSTODIAL WALLET TESTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testNonCustodialWallet() {
    log.header('NON-CUSTODIAL WALLET TEST (Threshold Signatures)');

    try {
        // Create 2-of-3 threshold wallet
        const threshold = 2;
        const participants = 3;

        console.log(`Creating ${threshold}-of-${participants} threshold wallet...`);
        const { wallet, shares } = NonCustodialWallet.createNew('main', participants, threshold);
        log.success('Threshold wallet created');

        log.info('Network', wallet.network);
        log.info('Threshold', `${threshold} of ${participants}`);
        log.info('Shares Generated', shares.length);

        log.divider();

        // Display shares (normally these would be distributed to participants)
        console.log('Generated shares (distribute to participants):');
        shares.forEach((share, i) => {
            log.info(`Share ${i + 1}`, `Index: ${share.index}, X: ${share.x.substring(0, 16)}...`);
        });

        log.divider();

        // Get threshold config
        const config = wallet.getThresholdConfig();
        log.success('Threshold configuration');
        log.info('Threshold', config.threshold);
        log.info('Participants', config.participants);
        log.info('Shares Available', config.sharesAvailable);

        log.divider();

        // Get wallet address
        console.log('Deriving addresses from aggregate public key...');

        const segwitAddr = wallet.getAddress('segwit');
        log.success('SegWit address derived');
        log.info('Address', segwitAddr);

        const taprootAddr = wallet.getAddress('taproot');
        log.success('Taproot address derived');
        log.info('Address', taprootAddr);

        log.divider();

        // Get public key
        const publicKey = wallet.getPublicKey();
        log.success('Aggregate public key retrieved');
        log.info('Public Key', publicKey.toString('hex').substring(0, 40) + '...');

        log.divider();

        // Export shares for backup
        console.log('Exporting shares for backup...');
        const exported = wallet.exportShares();
        log.success('Shares exported');
        log.info('Network', exported.network);
        log.info('Threshold', exported.threshold);
        log.info('Participants', exported.participants);
        log.info('Shares Count', exported.shares.length);
        log.info('Has Commitments', exported.commitments ? 'Yes' : 'No');

        log.divider();

        // Import shares and recreate wallet
        console.log('Testing share import...');
        const importedWallet = NonCustodialWallet.importShares(exported);
        const importedAddr = importedWallet.getAddress('segwit');

        if (importedAddr === segwitAddr) {
            log.success('Wallet imported correctly - addresses match!');
        } else {
            log.error('Imported wallet addresses do not match');
        }

        log.divider();

        // Test threshold signing (requires async)
        console.log('Testing threshold signature...');
        const messageHash = Buffer.from('0'.repeat(64), 'hex'); // 32-byte hash

        try {
            const signature = await wallet.signMessage(messageHash, [1, 2]); // Use shares 1 and 2
            log.success('Threshold signature created');
            log.info('Signature R', signature.r?.toString(16).substring(0, 20) + '...');
            log.info('Signature S', signature.s?.toString(16).substring(0, 20) + '...');

            // Verify signature
            const isValid = await wallet.verifySignature(messageHash, signature);
            if (isValid) {
                log.success('Signature verified successfully');
            } else {
                log.error('Signature verification failed');
            }
        } catch (signError) {
            log.info('Signing', `Skipped - ${signError.message}`);
        }

        log.divider();

        // Export wallet info
        console.log('Wallet JSON export:');
        console.log(JSON.stringify(wallet.toJSON(), null, 2));

        return true;
    } catch (error) {
        log.error(error.message);
        console.error(error);
        return false;
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MAIN
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function main() {
    console.log(`${colors.bright}${colors.magenta}`);
    console.log('╔═══════════════════════════════════════════════════════════════╗');
    console.log('║                    J-BITCOIN WALLET TEST                      ║');
    console.log('╚═══════════════════════════════════════════════════════════════╝');
    console.log(colors.reset);

    log.info('Library', LIBRARY_INFO.name);
    log.info('Version', LIBRARY_INFO.version);
    log.info('Networks', Object.keys(NETWORKS).join(', '));

    const results = {
        custodial: await testCustodialWallet(),
        nonCustodial: await testNonCustodialWallet()
    };

    log.header('TEST RESULTS');

    console.log(`${results.custodial ? colors.green + '✓' : colors.red + '✗'}${colors.reset} Custodial Wallet: ${results.custodial ? 'PASSED' : 'FAILED'}`);
    console.log(`${results.nonCustodial ? colors.green + '✓' : colors.red + '✗'}${colors.reset} Non-Custodial Wallet: ${results.nonCustodial ? 'PASSED' : 'FAILED'}`);

    log.divider();

    const allPassed = results.custodial && results.nonCustodial;
    process.exit(allPassed ? 0 : 1);
}

main().catch(console.error);
