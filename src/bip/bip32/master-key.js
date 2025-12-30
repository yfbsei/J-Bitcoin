/**
 * @fileoverview BIP32 master key generation from seed
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

import { createHmac, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { b58encode } from '../../encoding/base58.js';
import {
  CRYPTO_CONSTANTS,
  BIP32_CONSTANTS,
  NETWORK_VERSIONS,
  validateAndGetNetwork
} from '../../core/constants.js';

function secureClear(buffer) {
  if (Buffer.isBuffer(buffer)) {
    const randomData = randomBytes(buffer.length);
    randomData.copy(buffer);
    buffer.fill(0);
  }
}

function validateSeed(seed) {
  if (!seed) {
    throw new Error('Seed is required');
  }

  let seedBuffer;
  if (typeof seed === 'string') {
    seedBuffer = Buffer.from(seed, 'hex');
  } else if (Buffer.isBuffer(seed)) {
    seedBuffer = seed;
  } else {
    throw new Error('Seed must be a Buffer or hex string');
  }

  if (seedBuffer.length < BIP32_CONSTANTS.MIN_SEED_BYTES) {
    throw new Error(`Seed too short: ${seedBuffer.length} < ${BIP32_CONSTANTS.MIN_SEED_BYTES} bytes`);
  }

  if (seedBuffer.length > BIP32_CONSTANTS.MAX_SEED_BYTES) {
    throw new Error(`Seed too long: ${seedBuffer.length} > ${BIP32_CONSTANTS.MAX_SEED_BYTES} bytes`);
  }

  return seedBuffer;
}

function encodeExtendedKey(type, context) {
  const buffer = Buffer.alloc(BIP32_CONSTANTS.EXTENDED_KEY_LENGTH);
  let offset = 0;

  const versionBytes = type === 'private'
    ? context.versionBytes.extendedPrivateKey
    : context.versionBytes.extendedPublicKey;

  versionBytes.copy(buffer, offset);
  offset += 4;

  buffer.writeUInt8(context.depth, offset);
  offset += 1;

  context.parentFingerprint.copy(buffer, offset);
  offset += 4;

  buffer.writeUInt32BE(context.childIndex, offset);
  offset += 4;

  context.chainCode.copy(buffer, offset);
  offset += 32;

  if (type === 'private') {
    buffer.writeUInt8(0x00, offset);
    offset += 1;
    context.privateKey.keyMaterial.copy(buffer, offset);
  } else {
    context.publicKey.keyMaterial.copy(buffer, offset);
  }

  return b58encode(buffer);
}

function generateMasterKey(seed, network = 'main') {
  const seedBuffer = validateSeed(seed);
  const networkConfig = validateAndGetNetwork(network);

  const curveOrder = BigInt('0x' + CRYPTO_CONSTANTS.SECP256K1_ORDER);
  let hmacResult, masterKeyMaterial, chainCode;
  let attemptCount = 0;
  const maxAttempts = 5;

  while (attemptCount < maxAttempts) {
    attemptCount++;

    const hmac = createHmac('sha512', BIP32_CONSTANTS.MASTER_KEY_HMAC_KEY);
    hmacResult = hmac.update(seedBuffer).digest();

    masterKeyMaterial = hmacResult.slice(0, 32);
    chainCode = hmacResult.slice(32, 64);

    const keyBigInt = BigInt('0x' + masterKeyMaterial.toString('hex'));

    if (keyBigInt > 0n && keyBigInt < curveOrder) {
      break;
    }

    if (attemptCount >= maxAttempts) {
      throw new Error('Failed to generate valid master key after maximum attempts');
    }

    const hmacForSeed = createHmac('sha256', seedBuffer);
    const newSeed = hmacForSeed.update(Buffer.from([attemptCount])).digest();
    seedBuffer.fill(0);
    newSeed.copy(seedBuffer, 0, 0, Math.min(newSeed.length, seedBuffer.length));

    secureClear(masterKeyMaterial);
    secureClear(chainCode);
    secureClear(hmacResult);
  }

  const compressedPublicKey = Buffer.from(secp256k1.getPublicKey(masterKeyMaterial, true));
  const publicKeyPoint = secp256k1.ProjectivePoint.fromPrivateKey(masterKeyMaterial);

  const masterKeyContext = {
    versionBytes: {
      extendedPublicKey: networkConfig.versions.EXTENDED_PUBLIC_KEY,
      extendedPrivateKey: networkConfig.versions.EXTENDED_PRIVATE_KEY
    },
    depth: BIP32_CONSTANTS.MASTER_KEY_DEPTH,
    parentFingerprint: BIP32_CONSTANTS.ZERO_PARENT_FINGERPRINT,
    childIndex: BIP32_CONSTANTS.MASTER_CHILD_INDEX,
    chainCode: chainCode,
    privateKey: {
      keyMaterial: masterKeyMaterial,
      wifVersionByte: networkConfig.versions.WIF_PRIVATE_KEY
    },
    publicKey: {
      keyMaterial: compressedPublicKey,
      point: publicKeyPoint
    }
  };

  const extendedPrivateKey = encodeExtendedKey('private', masterKeyContext);
  const extendedPublicKey = encodeExtendedKey('public', masterKeyContext);

  const expectedPrefix = network === 'main' ? 'xprv' : 'tprv';
  if (!extendedPrivateKey.startsWith(expectedPrefix)) {
    throw new Error(`Invalid extended key prefix: expected ${expectedPrefix}`);
  }

  return [
    {
      extendedPrivateKey,
      extendedPublicKey
    },
    masterKeyContext
  ];
}

export { generateMasterKey, encodeExtendedKey, validateSeed };
export default generateMasterKey;
