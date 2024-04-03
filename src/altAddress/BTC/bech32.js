/*
References
https://en.bitcoin.it/wiki/BIP_0350
https://slowli.github.io/bech32-buffer/
https://bitcoin.sipa.be/bech32/demo/demo.html
https://medium.com/@meshcollider/some-of-the-math-behind-bech32-addresses-cf03c7496285
https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-Witness_program
https://bitcoin.stackexchange.com/questions/71212/understanding-bech32-addresses-bip173-question
https://unchained.com/blog/bitcoin-address-types-compared/
*/

import CASH_ADDR from '../BCH/cash_addr.js';
import base32_encode from '../../utilities/Base32.js';

const BECH32 = {

	encode(prefix = "bc", data = Uint8Array || Buffer, encoding = 'bech32') { // witness version == version byte, witness program == any data

		let checksum = Buffer.concat([
			this.expandHRP(prefix), // [high bits of HRP] + [0] + [low bits of HRP]
			data, // [data]
			Buffer.alloc(6) // [0,0,0,0,0,0]
		]);

		checksum = this.polymod(checksum) ^ (encoding === 'bech32' ? 1 : 0x2bc830a3);

		const payload = Buffer.concat([ // data + checksum
			data, // data
			CASH_ADDR.checksum_5bit(checksum).subarray(2) //checksum   /* bch's cashAddr uses 8byte template, btc's bech32/bech32m uses 6byte */
		]);

		return prefix + "1" + base32_encode(payload); // HRP + “1” + BinaryToBase32(data+checksum)
	},

	// https://en.bitcoin.it/wiki/BIP_0350
	polymod(values) {
		const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
		let chk = 1;
		for (let v of values) {
			let b = (chk >> 25);
			chk = (chk & 0x1ffffff) << 5 ^ v;
			for (let i = 0; i < 5; i++) {
				chk ^= ((b >> i) & 1) ? GEN[i] : 0;
			}
		}
		return chk;
	},

	expandHRP(prefix = "bc") { // expanding the prefix
		return Buffer.concat([
			new Uint8Array(prefix.length).map((_, i) => prefix[i].charCodeAt() >> 5), // upper 3 bits of each character
			Buffer.from([0]), // separater
			new Uint8Array(prefix.length).map((_, i) => prefix[i].charCodeAt() & 31) // lower 5 bits of each character
		]);
	},

/* ------------------------------------------------------------------ */

	to_P2WPKH(witness_program = "legacy address") { // P2PKH to P2WPKH
		let [bch_prefix, hash] = CASH_ADDR.decode_legacy_address(witness_program); // borrowing method from bch
		const btc_prefix = bch_prefix === "bitcoincash" ? 'bc' : 'tb';

		hash = Buffer.from(hash, 'hex');
		hash = CASH_ADDR.convertBits(hash, 8, 5); // Convert to 5 bits, 0.625 bytes

		const data = Buffer.concat([Buffer.from([0]), hash]); // witness_version + witness_program

		return this.encode(btc_prefix, data, 'bech32');
	},

	data_to_bech32(prefix = "Jamallo", data = "hex", encoding = 'bech32' || 'bech32m') {

		const hex_to_buffer = Buffer.from(data, 'hex');
		data = CASH_ADDR.convertBits(hex_to_buffer, 8, 5);

		const len = 2 * prefix.length + 1 + data.length + 6;
		if (len - prefix.length > 90) throw new Error("prefix or data is to long, total max length is 90");

		return this.encode(prefix, data, encoding);
	}

}

export default BECH32;
