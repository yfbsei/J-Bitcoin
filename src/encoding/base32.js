/**
 * @fileoverview Bech32/Bech32m encoding for Bitcoin SegWit and Taproot addresses
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/**
 * Compute Bech32 polymod checksum
 * @param {number[]} values - Values to checksum
 * @returns {number} Checksum value
 */
function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) {
        chk ^= GENERATOR[i];
      }
    }
  }
  return chk;
}

function hrpExpand(hrp) {
  const result = [];
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) >> 5);
  }
  result.push(0);
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) & 31);
  }
  return result;
}

function verifyChecksum(hrp, data, spec) {
  const constant = spec === 'bech32m' ? BECH32M_CONST : BECH32_CONST;
  return polymod(hrpExpand(hrp).concat(data)) === constant;
}

function createChecksum(hrp, data, spec) {
  const constant = spec === 'bech32m' ? BECH32M_CONST : BECH32_CONST;
  const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ constant;
  const result = [];
  for (let i = 0; i < 6; i++) {
    result.push((mod >> (5 * (5 - i))) & 31);
  }
  return result;
}

/**
 * Encode data as Bech32/Bech32m
 * @param {string} hrp - Human-readable part
 * @param {number[]} data - 5-bit values to encode
 * @param {string} [spec='bech32'] - Encoding spec ('bech32' or 'bech32m')
 * @returns {string} Encoded address
 */
function encode(hrp, data, spec = 'bech32') {
  const checksum = createChecksum(hrp, data, spec);
  const combined = data.concat(checksum);
  let result = hrp + '1';
  for (const d of combined) {
    result += CHARSET[d];
  }
  return result;
}

/**
 * Decode a Bech32/Bech32m string
 * @param {string} str - Bech32 string to decode
 * @returns {Object} Decoded {hrp, data, spec}
 * @throws {Error} If string invalid or checksum fails
 */
function decode(str) {
  if (str.length < 8 || str.length > 90) {
    throw new Error('Invalid bech32 string length');
  }

  const lowered = str.toLowerCase();
  const uppered = str.toUpperCase();

  if (str !== lowered && str !== uppered) {
    throw new Error('Mixed case in bech32 string');
  }

  const bech = lowered;
  const pos = bech.lastIndexOf('1');

  if (pos < 1 || pos + 7 > bech.length) {
    throw new Error('Invalid separator position');
  }

  const hrp = bech.slice(0, pos);
  const data = [];

  for (let i = pos + 1; i < bech.length; i++) {
    const idx = CHARSET.indexOf(bech[i]);
    if (idx === -1) {
      throw new Error(`Invalid character: ${bech[i]}`);
    }
    data.push(idx);
  }

  let spec = 'bech32';
  if (!verifyChecksum(hrp, data, 'bech32')) {
    if (verifyChecksum(hrp, data, 'bech32m')) {
      spec = 'bech32m';
    } else {
      throw new Error('Invalid checksum');
    }
  }

  return { hrp, data: data.slice(0, -6), spec };
}

/**
 * Convert between bit groupings
 * @param {number[]} data - Input values
 * @param {number} fromBits - Source bits per value
 * @param {number} toBits - Target bits per value
 * @param {boolean} [pad=true] - Add padding if needed
 * @returns {number[]} Converted values
 */
function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0;
  let bits = 0;
  const result = [];
  const maxv = (1 << toBits) - 1;

  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) {
      throw new Error('Invalid value for bit conversion');
    }
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.push((acc << (toBits - bits)) & maxv);
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('Invalid padding');
  }

  return result;
}

/**
 * Encode a SegWit address
 * @param {string} hrp - Human-readable part ('bc' or 'tb')
 * @param {number} version - Witness version (0-16)
 * @param {Buffer} program - Witness program
 * @returns {string} Bech32/Bech32m address
 */
function encodeSegwit(hrp, version, program) {
  if (version < 0 || version > 16) {
    throw new Error('Invalid witness version');
  }

  if (program.length < 2 || program.length > 40) {
    throw new Error('Invalid witness program length');
  }

  if (version === 0 && program.length !== 20 && program.length !== 32) {
    throw new Error('Invalid witness program length for v0');
  }

  const spec = version === 0 ? 'bech32' : 'bech32m';
  const data = [version].concat(convertBits(Array.from(program), 8, 5));

  return encode(hrp, data, spec);
}

/**
 * Decode a SegWit address
 * @param {string} hrp - Expected human-readable part
 * @param {string} addr - Bech32 address to decode
 * @returns {Object} Decoded {version, program}
 * @throws {Error} If address invalid
 */
function decodeSegwit(hrp, addr) {
  const { hrp: decodedHrp, data, spec } = decode(addr);

  if (decodedHrp !== hrp) {
    throw new Error('HRP mismatch');
  }

  if (data.length < 1) {
    throw new Error('Empty data');
  }

  const version = data[0];

  if (version > 16) {
    throw new Error('Invalid witness version');
  }

  if (version === 0 && spec !== 'bech32') {
    throw new Error('Version 0 must use bech32');
  }

  if (version !== 0 && spec !== 'bech32m') {
    throw new Error('Version 1+ must use bech32m');
  }

  const program = Buffer.from(convertBits(data.slice(1), 5, 8, false));

  if (program.length < 2 || program.length > 40) {
    throw new Error('Invalid program length');
  }

  if (version === 0 && program.length !== 20 && program.length !== 32) {
    throw new Error('Invalid v0 program length');
  }

  return { version, program };
}

export {
  encode,
  decode,
  encodeSegwit,
  decodeSegwit,
  convertBits,
  CHARSET,
  BECH32_CONST,
  BECH32M_CONST
};

export default {
  encode,
  decode,
  encodeSegwit,
  decodeSegwit,
  convertBits
};
