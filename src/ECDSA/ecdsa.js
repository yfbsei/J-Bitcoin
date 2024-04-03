import { createHmac } from 'node:crypto';
import { signSync, verify as verifySync, recoverPublicKey, utils } from '@noble/secp256k1';
import { privateKey_decode } from '../utilities/decodeKeys.js';

utils.hmacSha256Sync = (key, ...messages) => {
    const hash = createHmac('sha256', key);
    messages.forEach((m) => hash.update(m));
    return Uint8Array.from(hash.digest());
}

const ECDSA = {

    sign(private_key = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", msg = "Hello world") {
        msg = Buffer.from(msg);
        private_key = privateKey_decode(private_key);
        return signSync(msg, private_key, {recovered: true}); 
    },

    verify(sig = Uint8Array || Buffer, msg = "Hello World", public_key = Uint8Array || Buffer) {
        msg = Buffer.from(msg);
        return verifySync(sig, msg, public_key);
    },

    retrieve_public_key(msg = "Hello world", sig = Uint8Array || Buffer, recovery = 0) {
        msg = Buffer.from(msg);
        return recoverPublicKey(msg, sig, recovery, true);
    }
}


// const 
//     [private_key, message] = ["L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS", "Jamallo"],
//     [sig, recovery] = ECDSA.sign(private_key, message),
//     public_key = ECDSA.retrieve_public_key(message, sig, recovery);

// ECDSA.verify(sig, message, public_key) // true

export default ECDSA;
