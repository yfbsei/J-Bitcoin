import { createHash } from 'node:crypto';
import b58encode from './base58.js';
import rmd160 from './rmd160.js';

const hdKey = (keyType = 'pri' || 'pub', {versionByte, depth, parentFingerPrint, childIndex, chainCode, privKey, pubKey}) => {
	const
		buf = Buffer.alloc(4),
		buf1 = Buffer.alloc(1),
		buf2 = Buffer.alloc(4),
		buf3 = Buffer.alloc(1);

	buf.writeUInt32BE(keyType === 'pri' ? versionByte.privKey : versionByte.pubKey, 0);
	buf1.writeInt8(depth, 0);
	buf2.writeUInt32BE(childIndex, 0);
	buf3.writeUInt8(0, 0);

	const bufferKey = Buffer.concat([  // Serialize
		buf,
		buf1,
		parentFingerPrint,
		buf2,
		chainCode,
		keyType === 'pri' ? buf3 : null,
		keyType === 'pri' ? privKey.key : pubKey.key
	].filter(x => x));
	// Filter out null

	return b58encode(bufferKey); // Readable key
}

const standardKey = (privKey, pubKey) => {
	let privite_key = null;

	if(privKey) {
		const privKey1 = {
			prefix: Buffer.from([privKey.versionByteNum]),
			key: privKey.key,
			suffix: Buffer.from([0x01])
		};

		const priKeyByte = Buffer.concat([privKey1.prefix, privKey1.key, privKey1.suffix]); // Standard private-key byte
		privite_key = b58encode(priKeyByte);
	}	
	
	const pub = pubKey ? pubKey.key.toString('hex') : pubKey;

	return {
		pri: privite_key, // Readable standard private key
		pub: pub // Readable standard public key
	}
}


const address = (versionByte, pubKey) => {
	const
		pubKeyHash = versionByte === 0x0488b21e ? 0x00: 0x6f, // Mainnet or Testnet
        prefix = Buffer.from([pubKeyHash]),
		hashBuf = rmd160( createHash('sha256').update(pubKey).digest() ), // rmd160(sha256)
		addressByte = Buffer.concat([prefix, hashBuf]); // Address byte
	
	return b58encode(addressByte); // Readable Address
}

export {
	hdKey,
	standardKey,
	address
};
