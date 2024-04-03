"use strict";

const hs = Array.from(Array(16), (_, i) => i.toString(16));
const hsr = hs.slice().reverse();
const h2s =  hs.join("").match(/../g), h2sr = hsr.join("").match(/../g);
const h2mix = hs.map((h, i) => `${hsr[i]}${h}`);
const hseq = h2s.concat(h2sr, h2mix).map(hex => parseInt(hex, 16));
const H = new Uint32Array(Uint8Array.from(hseq.slice(0, 20)).buffer);
const KL = Uint32Array.from(
    [0, 2, 3, 5, 7], v => Math.floor(Math.sqrt(v) * (2 ** 30)));
const KR = Uint32Array.from(
    [2, 3, 5, 7, 0], v => Math.floor(Math.cbrt(v) * (2 ** 30)));
const IL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
const IR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
const SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
const SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
const FL = [
    (b, c, d) => (b ^ c ^ d) >>> 0,
    (b, c, d) => ((b & c) | ((~b >>> 0) & d)) >>> 0,
    (b, c, d) => ((b | (~c >>> 0)) ^ d) >>> 0,
    (b, c, d) => ((b & d) | (c & (~d >>> 0))) >>> 0,
    (b, c, d) => (b ^ (c | (~d >>> 0))) >>> 0,
];
const FR = FL.slice().reverse();
function rotl(v, n) {
    return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function rmd160(buffer) {
    const u8a = ArrayBuffer.isView(buffer) ?
          new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength) :
          new Uint8Array(buffer);
          
    const total = Math.ceil((u8a.length + 9) / 64) * 64;
    const chunks = new Uint8Array(total);
    chunks.set(u8a);
    chunks.fill(0, u8a.length);
    chunks[u8a.length] = 0x80;
    const lenbuf = new Uint32Array(chunks.buffer, total - 8);
    const low = u8a.length % (1 << 29);
    const high = (u8a.length - low) / (1 << 29);
    lenbuf[0] = low << 3;
    lenbuf[1] = high;
    
    const hash = H.slice();
    for (let offs = 0; offs < total; offs += 64) {
        const w = new Uint32Array(chunks.buffer, offs, 16);
        let [al, bl, cl, dl, el] = hash, [ar, br, cr, dr, er] = hash;
        for (let s = 0; s < 5; s++) {
            for (let i = s * 16, end = i + 16; i < end; i++) {
                const tl = al + FL[s](bl, cl, dl) + w[IL[i]] + KL[s];
                const nal = (rotl(tl >>> 0, SL[i]) + el) >>> 0;
                [al, bl, cl, dl, el] = [el, nal, bl, rotl(cl, 10), dl];
                const tr = ar + FR[s](br, cr, dr) + w[IR[i]] + KR[s];
                const nar = (rotl(tr >>> 0, SR[i]) + er) >>> 0;
                [ar, br, cr, dr, er] = [er, nar, br, rotl(cr, 10), dr];
            }
        }
        hash.set([hash[1] + cl + dr, hash[2] + dl + er, hash[3] + el + ar,
                  hash[4] + al + br, hash[0] + bl + cr]);
    }
    return Buffer.from(hash.buffer);
}

export default rmd160;