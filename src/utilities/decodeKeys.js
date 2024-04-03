import { base58_to_binary } from 'base58-js';

function privateKey_decode(pri_key = "L1vHfV6GUbMJSvFaqjnButzwq5x4ThdFaotpUgsfScwMNKjdGVuS") {
    return base58_to_binary(pri_key).filter((_, i) => i > 0 && i < 33); // remove prefix and suffix
}

function legacyAddress_decode(legacy_addr = "1EiBTNS9Dqhjhk7D78GMAjK9pZn5NXZf91") {
    return base58_to_binary(legacy_addr).filter((_, i) => i > 0 && i < 21 ); // remove prefix and suffix
}

export { privateKey_decode, legacyAddress_decode };