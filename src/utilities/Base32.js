const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const base32_encode = data => data.reduce((base32, x) => base32 + CHARSET[x], '');

export default base32_encode;
