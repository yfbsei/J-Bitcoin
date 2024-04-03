import { createHmac } from 'node:crypto';
import { Buffer } from 'node:buffer';

import { hdKey } from '../utilities/encodeKeys.js';
import {Point, getPublicKey} from '@noble/secp256k1';

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
const fromSeed = (seed, net = 'main' || 'test') => {
	seed = Buffer.from(seed, 'hex');

	const 
	hashHmac = createHmac('sha512', Buffer.from("Bitcoin seed")).update(seed).digest(),
	[IL, IR] = [hashHmac.slice(0, 32), hashHmac.slice(32, 64)],
	serialization_format = { // Serialization format
		versionByte: {
			pubKey: net === 'main' ? 0x0488b21e : 0x043587cf,
			privKey: net === 'main' ? 0x0488ade4 : 0x04358394
		},
		depth: 0x00,
		parentFingerPrint: Buffer.from([0, 0, 0, 0]),
		childIndex: 0x00000000,
		chainCode: IR, // Master chain code
        privKey: { // Master private key
			key: IL,
			versionByteNum: net === 'main' ? 0x80 : 0xef
		},
        pubKey: {
			key: Buffer.from(getPublicKey(IL, true)),
			points: Point.fromPrivateKey(IL)
		}
	}
	return [
		{
			HDpri: hdKey('pri', serialization_format),
			HDpub: hdKey('pub', serialization_format),
		},
		serialization_format
	];
}

export default fromSeed;
