import { binary_to_base58 } from 'base58-js';
import { createHash } from 'node:crypto';

const table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58encode(bufferKey) {

  // Check
  const checkedBuf = Buffer.alloc(bufferKey.length + 4);
  bufferKey.copy(checkedBuf);
  createHash('sha256').update( createHash('sha256').update(bufferKey).digest() ).digest().copy(checkedBuf, bufferKey.length);

  // Encode
  return binary_to_base58(Uint8Array.from(checkedBuf))
}

export default b58encode