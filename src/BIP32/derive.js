import { createHmac, createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

import rmd160 from '../utilities/rmd160.js';

import {Point, getPublicKey} from '@noble/secp256k1';
import { hdKey } from '../utilities/encodeKeys.js';

import BN from 'bn.js';

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
const derive = ( path, key = '', serialization_format ) => {
    
    const keyType = key.slice(0, 4).slice(1) === 'prv'; // Working with private or public key
    if(!keyType && path.includes("'")) {throw new Error("Public Key can't derive from hardend path")}
    
    const N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 'hex');

    const numPath = path.split('/').filter(x => !isNaN(parseInt(x))).map(x => x[x.length -1] === "'" ? (parseInt(x) & 0x7fffffff) + 0x80000000 : parseInt(x)); // Harden the path
    
    const serializedByte = numPath.map(y => // serialize Int as 4-byte
        Buffer.from([ 
            (y & 0xff000000) >> 24,
            (y & 0x00ff0000) >> 16,
            (y & 0x0000ff00) >> 8,
            (y & 0x000000ff)
        ])
    );

    for (let i = 0, hashHmac, ki; i < numPath.length; i++) {
        const {versionByte, depth, parentFingerPrint, childIndex, chainCode, privKey, pubKey} = serialization_format;

    hashHmac = createHmac('sha512', chainCode).update(  
        keyType ? (numPath[i] >= 0x80000000) ? Buffer.concat([ Buffer.from([0x00]), privKey.key, serializedByte[i] ]) :
        Buffer.concat( [pubKey.key, serializedByte[i]] ) : 
        Buffer.concat( [pubKey.key, serializedByte[i]] )
        ).digest();
        
        const [IL, IR] = [hashHmac.slice(0, 32), hashHmac.slice(32, 64)];

        ki = keyType ?
        new BN(IL).add(new BN(privKey.key)).mod(N).toBuffer() // ki = IL + kpar (mod n)
        : Point.fromPrivateKey(IL).add(pubKey.points); // IL*G + Kpar

        serialization_format = { // Serialization format
            versionByte: versionByte,
        	depth: depth + 1,
        	parentFingerPrint: rmd160(createHash('sha256').update(pubKey.key).digest()).slice(0, 4),
        	childIndex: numPath[i],
        	chainCode: IR,
        	privKey: keyType ? {
        		key: ki, // Buffer
        		versionByteNum: privKey.versionByteNum
        	} : null,
        	pubKey: keyType ? {
                key: Buffer.from(getPublicKey(ki, true)),
                points: Point.fromPrivateKey(ki)
            } : {
                key: Buffer.from(ki.toRawBytes(true)),
                points: ki
            }
        }
    }

    return [
    	{
    		HDpri: keyType ? hdKey('pri', serialization_format) : null,
    		HDpub: hdKey('pub', serialization_format),
    	},
        serialization_format
    ];
}

export default derive;
