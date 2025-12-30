/**
 * @fileoverview RIPEMD160 cryptographic hash function implementation
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHash } from 'node:crypto';

const SECURITY_CONSTANTS = {
  MAX_INPUT_SIZE: 1024 * 1024,
  MAX_VALIDATIONS_PER_SECOND: 1000,
  VALIDATION_TIMEOUT_MS: 1000,
  MEMORY_CLEAR_PASSES: 3,
  HASH_OUTPUT_SIZE: 20,
  BLOCK_SIZE: 64,
  STATE_SIZE: 5
};

const H = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
const KL = new Uint32Array([0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]);
const KR = new Uint32Array([0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]);

const IL = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
];

const IR = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
];

const SL = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
];

const SR = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
];

const FL = [
  (b, c, d) => b ^ c ^ d,
  (b, c, d) => (b & c) | (~b & d),
  (b, c, d) => (b | ~c) ^ d,
  (b, c, d) => (b & d) | (c & ~d),
  (b, c, d) => b ^ (c | ~d)
];

const FR = [
  (b, c, d) => b ^ (c | ~d),
  (b, c, d) => (b & d) | (c & ~d),
  (b, c, d) => (b | ~c) ^ d,
  (b, c, d) => (b & c) | (~b & d),
  (b, c, d) => b ^ c ^ d
];

function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function secureClear(data) {
  if (data instanceof Uint8Array || data instanceof Uint32Array) {
    for (let pass = 0; pass < SECURITY_CONSTANTS.MEMORY_CLEAR_PASSES; pass++) {
      for (let i = 0; i < data.length; i++) {
        data[i] = Math.random() * 256 | 0;
      }
    }
    data.fill(0);
  }
}

function rmd160(buffer) {
  if (!buffer) {
    throw new Error('Input buffer is required');
  }

  let inputBuffer;
  if (ArrayBuffer.isView(buffer)) {
    inputBuffer = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } else if (buffer instanceof ArrayBuffer) {
    inputBuffer = new Uint8Array(buffer);
  } else {
    throw new Error('Input must be ArrayBuffer, TypedArray, or Buffer');
  }

  if (inputBuffer.length > SECURITY_CONSTANTS.MAX_INPUT_SIZE) {
    throw new Error(`Input too large: ${inputBuffer.length} > ${SECURITY_CONSTANTS.MAX_INPUT_SIZE}`);
  }

  const total = Math.ceil((inputBuffer.length + 9) / 64) * 64;
  const processedChunks = new Uint8Array(total);

  processedChunks.set(inputBuffer);
  processedChunks.fill(0, inputBuffer.length);
  processedChunks[inputBuffer.length] = 0x80;

  const lengthBuffer = new Uint32Array(processedChunks.buffer, total - 8);
  const lowBits = inputBuffer.length % (1 << 29);
  const highBits = (inputBuffer.length - lowBits) / (1 << 29);
  lengthBuffer[0] = lowBits << 3;
  lengthBuffer[1] = highBits;

  const hashState = new Uint32Array(H);

  for (let offset = 0; offset < total; offset += 64) {
    const messageBlock = new Uint32Array(processedChunks.buffer, offset, 16);
    let [al, bl, cl, dl, el] = hashState;
    let [ar, br, cr, dr, er] = hashState;

    for (let round = 0; round < 5; round++) {
      for (let i = round * 16, end = i + 16; i < end; i++) {
        const leftTemp = al + FL[round](bl, cl, dl) + messageBlock[IL[i]] + KL[round];
        const newAl = (rotl(leftTemp >>> 0, SL[i]) + el) >>> 0;
        [al, bl, cl, dl, el] = [el, newAl, bl, rotl(cl, 10), dl];

        const rightTemp = ar + FR[round](br, cr, dr) + messageBlock[IR[i]] + KR[round];
        const newAr = (rotl(rightTemp >>> 0, SR[i]) + er) >>> 0;
        [ar, br, cr, dr, er] = [er, newAr, br, rotl(cr, 10), dr];
      }
    }

    const temp = (hashState[1] + cl + dr) >>> 0;
    hashState[1] = (hashState[2] + dl + er) >>> 0;
    hashState[2] = (hashState[3] + el + ar) >>> 0;
    hashState[3] = (hashState[4] + al + br) >>> 0;
    hashState[4] = (hashState[0] + bl + cr) >>> 0;
    hashState[0] = temp;
  }

  const result = Buffer.allocUnsafe(SECURITY_CONSTANTS.HASH_OUTPUT_SIZE);
  for (let i = 0; i < SECURITY_CONSTANTS.STATE_SIZE; i++) {
    result.writeUInt32LE(hashState[i], i * 4);
  }

  secureClear(processedChunks);
  secureClear(hashState);

  return result;
}

function hash160(buffer) {
  const sha256Hash = createHash('sha256').update(buffer).digest();
  return rmd160(sha256Hash);
}

export default rmd160;
export { rmd160, hash160 };
