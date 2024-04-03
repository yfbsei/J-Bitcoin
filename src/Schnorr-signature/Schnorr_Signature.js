/*
https://github.com/bitcoin-core/secp256k1/blob/0fa84f869d51e1b71113d81fcd518ebcee08709a/include/secp256k1_schnorrsig.h#L113-L117
*/
import { randomBytes, createHash } from 'node:crypto';
import { schnorr, utils } from '@noble/secp256k1';
import { privateKey_decode } from '../utilities/decodeKeys.js';

utils.sha256Sync = (messages) => {
    return createHash('sha256').update(messages).digest();
}

const schnorr_sig = {
    sign(private_key = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", msg = "Hello world", auxRand = randomBytes(32)) {
        msg = Buffer.from(msg);
        private_key = privateKey_decode(private_key);
        return schnorr.signSync(msg, private_key, auxRand)
    },

    verify(sig = Uint8Array || Buffer, msg = "Hello World", public_key = Uint8Array || Buffer) {
        msg = Buffer.from(msg);
        return schnorr.verifySync(sig, msg, public_key)
    },

    retrieve_public_key(private_key = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS") {
        private_key = privateKey_decode(private_key);
        return schnorr.getPublicKey(private_key)
    }
}

export default schnorr_sig;