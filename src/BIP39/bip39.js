import { createHash, randomBytes, pbkdf2Sync } from 'node:crypto';
import wordList_en from './wordList_en.js';

const BIP39 = {

	mnemonic() {

		const
			buf = randomBytes(16), // Buffer
			hash = createHash('sha256').update(buf).digest(), // sha256 Hash
			bin = buf.reduce((str, byte) => str + byte.toString(2).padStart(8, '0'), '') + ('00000000' + hash[0].toString(2)).slice(-8).slice(0, (16 * 8) / 32); // Binary

		return [...Array(12).keys()].map(i => parseInt(bin.slice(i * 11, (i + 1) * 11), 2)).map(w => wordList_en[w]).toString().replaceAll(',', ' '); // Mnemonic
	},

	seed(mnemonic = '', passphrase = '') {

		// Buffer
		const 
		secret = Buffer.from(mnemonic),
		salt = Buffer.concat([
			Buffer.from('mnemonic'),
			Buffer.from(passphrase)
		]),
		seed = pbkdf2Sync(secret, salt, 2048, 64, 'sha512');
		
		return seed.toString('hex');
	},

	checkSum(mnemonic = '') {

		const
			bin = mnemonic.split(' ').map(x => wordList_en.indexOf(x)).reduce((str, byte) => str + byte.toString(2).padStart(11, '0'), ''), // Binary
			buf = Buffer.from([...Array(16).keys()].map(i => parseInt(bin.slice(i * 8, (i + 1) * 8), 2))), // Buffer
			hash = createHash('sha256').update(buf).digest(); // sha256 Hash

		return [hash[0].toString(2)].reduce((str, byte) => str + byte.toString(2).padStart(8, '0'), '').slice(0, 4) === bin.slice(-4);
	},

	random(passphrase = '') {
		const mnemonic = this.mnemonic();
		if(this.checkSum(mnemonic)) {
			return {
				mnemonic,
				seed: this.seed(mnemonic, passphrase)
			}
		} 
		else {
			throw 'invalid checksum';
		}
	},

	mnemonic2seed(mnemonic = '', passphrase = '') {
		if(this.checkSum(mnemonic)) {
			return this.seed(mnemonic, passphrase);
		}
		else {
			throw 'invalid checksum';
		}
	}
	
}

export default BIP39; 