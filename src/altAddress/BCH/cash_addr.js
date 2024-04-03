/*
References
 https://github.com/Bitcoin-ABC/bitcoin-abc/blob/72728b657cf50ba20de681b048d57d7ff9ae46ec/modules/ecashaddrjs/src/cashaddr.js#L178
 https://reference.cash/protocol/blockchain/encoding/cashaddr
 https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
*/

import BN from 'bn.js';
import { base58_to_binary } from 'base58-js';
import base32_encode from '../../utilities/Base32.js';


const CASH_ADDR = {

	to_cashAddr(legacy_address = "", type = "p2pkh") {
        let [prefix, hash] = this.decode_legacy_address(legacy_address);  // decode legacy address
		
        hash = Buffer.from(hash, 'hex');
        hash = Buffer.concat( [this.versionByte(type, hash), hash] ); // (versionByte + hash);

		const payload = this.convertBits(hash, 8, 5); // Convert to 5 bits, 0.625 bytes

        // polymod( prefix + separator + payload + template )
		const checksum = 
		this.polymod(
            Buffer.concat([
                this.prefix_5bit(prefix), 
                Buffer.alloc(1), 
                payload, 
                Buffer.alloc(8)])
            );

		return prefix.toLowerCase() + ':' + base32_encode(payload) + base32_encode( this.checksum_5bit(checksum) ); // prefix + payload_base32 + checksum_base32
	},

	decode_legacy_address(legacy_addr = "") {
		let legacy_addr_bytes = base58_to_binary(legacy_addr);
		const prefix = legacy_addr_bytes[0] === 0 ? "bitcoincash" : "bchtest";

		if ( (legacy_addr_bytes[0] === 0 || legacy_addr_bytes[0] === 111) && legacy_addr_bytes.length === 25 ) {
			
            const legacy_addr_hash = legacy_addr_bytes.filter((_, i) => i > 0 && i < 21 ); // remove legacy prefix and suffix
			return [prefix, Buffer.from(legacy_addr_hash).toString('hex')]; // [bch-prefix, hash]

		} else throw new Error("Invalid legacy address");
	},

	// https://reference.cash/protocol/blockchain/encoding/cashaddr
    polymod(v) { 
        let c = BigInt(1);
        for (let d of v) {
            let c0 = c >> BigInt(35);
            c = ((c & BigInt("0x07ffffffff")) << BigInt(5)) ^ BigInt(d);
            if (c0 & 0x01n) c ^= BigInt("0x98f2bc8e61");
            if (c0 & 0x02n) c ^= BigInt("0x79b76d99e2");
            if (c0 & 0x04n) c ^= BigInt("0xf33e5fb3c4");
            if (c0 & 0x08n) c ^= BigInt("0xae2eabe2a8");
            if (c0 & 0x10n) c ^= BigInt("0x1e4f43e470");
        }
        return Number(c ^ BigInt(1));
    },

	versionByte(type = "p2pkh", hash = Buffer) {

		const hashSizeBits = [160, 192, 224, 256, 320, 384, 448, 512]
        .map((x, i) => x === hash.length * 8 ? i : null)
        .filter(x => Number.isInteger(x))[0];

		const typeBits =
			type.toLowerCase() === "p2pkh" ? 0 :
			type.toLowerCase() === "p2sh" ? 8 :
			null;

		if (hashSizeBits === undefined || typeBits === null) throw new Error("Invalid hash size or invalid type");
		else {
			const ver_byte = Buffer.alloc(1);
			ver_byte.writeUInt8(typeBits + hashSizeBits); // verison number to verison byte 
			return ver_byte;
		}
	},

	prefix_5bit(prefix = 'bitcoincash') {
		return new Uint8Array(prefix.length).map((_, i) => prefix[i].charCodeAt() & 31); // lower 5 bits of each character
	},

	convertBits(data, from, to) {
		let [mask, result, index, accumulator, bits] = [ (1 << to) - 1, new Uint8Array(Math.ceil((data.length * from) / to)), 0, 0, 0 ];

		for (let i = 0; i < data.length; ++i) {
			let value = data[i];
			accumulator = (accumulator << from) | value;
			bits += from;
			while (bits >= to) {
				bits -= to;
				result[index] = (accumulator >> bits) & mask;
				++index;
			}
		}
		if (bits > 0) {
			result[index] = (accumulator << (to - bits)) & mask;
			++index;
		}
		return result;
	},

	checksum_5bit(checksum = 19310) {
		checksum = new BN(checksum);
		let result = new Uint8Array(8);
		for (let i = 0; i < 8; i++) {
			result[7 - i] = checksum.and(new BN(31))
			checksum = checksum.ushrn(5);
		}
		return result;
	}

}

export default CASH_ADDR;
