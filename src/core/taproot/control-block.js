/**
 * @fileoverview Taproot control block implementation following BIP341
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { TaprootMerkleTree, TaggedHash, MERKLE_CONSTANTS } from './merkle-tree.js';
import { CRYPTO_CONSTANTS } from '../constants.js';

class ControlBlockError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'ControlBlockError';
    this.code = code;
    this.details = details;
  }
}

const CONTROL_BLOCK_CONSTANTS = {
  BASE_SIZE: 33,
  HASH_SIZE: 32,
  MIN_SIZE: 33,
  MAX_SIZE: 33 + (32 * 128),
  LEAF_VERSION_MASK: 0xfe,
  PARITY_MASK: 0x01,
  DEFAULT_LEAF_VERSION: 0xc0,
  MAX_MERKLE_DEPTH: 128
};

class TaprootControlBlock {
  constructor() {
    this.validationCache = new Map();
  }

  parseControlBlock(controlBlock) {
    if (!Buffer.isBuffer(controlBlock)) {
      throw new ControlBlockError('Control block must be a Buffer', 'INVALID_TYPE');
    }

    if (controlBlock.length < CONTROL_BLOCK_CONSTANTS.MIN_SIZE) {
      throw new ControlBlockError('Control block too small', 'TOO_SMALL');
    }

    if (controlBlock.length > CONTROL_BLOCK_CONSTANTS.MAX_SIZE) {
      throw new ControlBlockError('Control block too large', 'TOO_LARGE');
    }

    const remainingSize = controlBlock.length - CONTROL_BLOCK_CONSTANTS.BASE_SIZE;
    if (remainingSize % CONTROL_BLOCK_CONSTANTS.HASH_SIZE !== 0) {
      throw new ControlBlockError('Invalid control block size', 'INVALID_SIZE');
    }

    const leafVersionAndParity = controlBlock[0];
    const leafVersion = leafVersionAndParity & CONTROL_BLOCK_CONSTANTS.LEAF_VERSION_MASK;
    const parity = leafVersionAndParity & CONTROL_BLOCK_CONSTANTS.PARITY_MASK;

    const internalKey = controlBlock.slice(1, 33);
    const merklePathData = controlBlock.slice(33);
    const merkleDepth = merklePathData.length / CONTROL_BLOCK_CONSTANTS.HASH_SIZE;

    const merklePath = [];
    for (let i = 0; i < merkleDepth; i++) {
      const start = i * CONTROL_BLOCK_CONSTANTS.HASH_SIZE;
      const end = start + CONTROL_BLOCK_CONSTANTS.HASH_SIZE;
      merklePath.push(merklePathData.slice(start, end));
    }

    return {
      leafVersion,
      parity,
      internalKey,
      merklePath,
      merkleDepth,
      isValid: true
    };
  }

  verifyScriptInclusion(script, controlBlock, expectedOutputKey) {
    const parsed = this.parseControlBlock(controlBlock);
    const { leafVersion, parity, internalKey, merklePath } = parsed;

    const tapLeafHash = TaggedHash.createTapLeaf(leafVersion, script);
    let computedRoot = tapLeafHash;

    for (const siblingHash of merklePath) {
      computedRoot = TaggedHash.createTapBranch(computedRoot, siblingHash);
    }

    if (merklePath.length === 0) {
      computedRoot = tapLeafHash;
    }

    const tapTweak = this.computeTapTweak(internalKey, computedRoot);
    const expectedKey = this.tweakInternalKey(internalKey, tapTweak, parity);

    const isValid = expectedKey.equals(expectedOutputKey);

    return {
      isValid,
      computedRoot,
      expectedOutputKey: expectedKey,
      metrics: {
        merkleDepth: merklePath.length,
        leafHash: tapLeafHash,
        tapTweak
      }
    };
  }

  generateControlBlock(merkleTree, leafIndex, internalKey, outputKeyParity) {
    if (!(merkleTree instanceof TaprootMerkleTree)) {
      throw new ControlBlockError('Invalid merkle tree', 'INVALID_TREE');
    }

    if (!Buffer.isBuffer(internalKey) || internalKey.length !== 32) {
      throw new ControlBlockError('Internal key must be 32 bytes', 'INVALID_KEY');
    }

    const leaf = merkleTree.getLeaf(leafIndex);
    const merklePath = merkleTree.getMerklePath(leafIndex);

    const firstByte = (leaf.leafVersion & CONTROL_BLOCK_CONSTANTS.LEAF_VERSION_MASK) |
                      (outputKeyParity & CONTROL_BLOCK_CONSTANTS.PARITY_MASK);

    const parts = [
      Buffer.from([firstByte]),
      internalKey,
      ...merklePath.hashes
    ];

    return Buffer.concat(parts);
  }

  computeTapTweak(internalKey, merkleRoot = null) {
    return TaggedHash.createTapTweak(internalKey, merkleRoot);
  }

  tweakInternalKey(internalKey, tapTweak, expectedParity = null) {
    const internalKeyBigInt = BigInt('0x' + internalKey.toString('hex'));
    const tweakBigInt = BigInt('0x' + tapTweak.toString('hex'));

    const point = secp256k1.ProjectivePoint.fromHex(
      Buffer.concat([Buffer.from([0x02]), internalKey])
    );

    const tweakPoint = secp256k1.ProjectivePoint.BASE.multiply(tweakBigInt);
    const outputPoint = point.add(tweakPoint);
    const outputKey = Buffer.from(outputPoint.toRawBytes(true)).slice(1);

    if (expectedParity !== null) {
      const actualParity = outputPoint.toRawBytes(true)[0] === 0x03 ? 1 : 0;
      if (actualParity !== expectedParity) {
        const negatedPoint = outputPoint.negate();
        return Buffer.from(negatedPoint.toRawBytes(true)).slice(1);
      }
    }

    return outputKey;
  }

  validateAgainstTree(controlBlock, merkleTree, leafIndex) {
    try {
      const parsed = this.parseControlBlock(controlBlock);
      const expectedPath = merkleTree.getMerklePath(leafIndex);

      if (parsed.merklePath.length !== expectedPath.hashes.length) {
        return false;
      }

      for (let i = 0; i < parsed.merklePath.length; i++) {
        if (!parsed.merklePath[i].equals(expectedPath.hashes[i])) {
          return false;
        }
      }

      return true;
    } catch {
      return false;
    }
  }
}

export {
  TaprootControlBlock,
  ControlBlockError,
  CONTROL_BLOCK_CONSTANTS
};
