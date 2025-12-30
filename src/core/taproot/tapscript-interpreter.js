/**
 * @fileoverview Tapscript interpreter implementation following BIP342
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

import { createHash, randomBytes } from 'node:crypto';
import Schnorr from '../crypto/signatures/schnorr-BIP340.js';
import { CRYPTO_CONSTANTS } from '../constants.js';

class TapscriptError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'TapscriptError';
    this.code = code;
    this.details = details;
  }
}

const TAPSCRIPT_CONSTANTS = {
  MAX_STACK_SIZE: 1000,
  MAX_SCRIPT_SIZE: 10000,
  MAX_ELEMENT_SIZE: 520,
  MAX_OPS_PER_SCRIPT: 201,
  BASE_SIGOPS_BUDGET: 50,
  SIGOPS_PER_WITNESS_UNIT: 1,
  LEAF_VERSION_TAPSCRIPT: 0xc0,
  MAX_SCRIPT_NUM_SIZE: 4,
  MAX_PUBKEYS_PER_MULTISIG: 20
};

const OPCODES = {
  OP_0: 0x00,
  OP_PUSHDATA1: 0x4c,
  OP_PUSHDATA2: 0x4d,
  OP_PUSHDATA4: 0x4e,
  OP_1NEGATE: 0x4f,
  OP_1: 0x51,
  OP_16: 0x60,
  OP_NOP: 0x61,
  OP_IF: 0x63,
  OP_NOTIF: 0x64,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_RETURN: 0x6a,
  OP_DUP: 0x76,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_HASH160: 0xa9,
  OP_HASH256: 0xaa,
  OP_CHECKSIG: 0xac,
  OP_CHECKSIGVERIFY: 0xad,
  OP_CHECKMULTISIG: 0xae,
  OP_CHECKSIGADD: 0xba,
  OP_SUCCESS_START: 0x50,
  OP_SUCCESS_END: 0xfe
};

class ScriptNum {
  static decode(buffer) {
    if (buffer.length === 0) return 0;

    if (buffer.length > TAPSCRIPT_CONSTANTS.MAX_SCRIPT_NUM_SIZE) {
      throw new TapscriptError('Script number too large', 'NUMBER_TOO_LARGE');
    }

    let result = 0;
    for (let i = 0; i < buffer.length; i++) {
      result |= buffer[i] << (8 * i);
    }

    if (buffer[buffer.length - 1] & 0x80) {
      result = -(result & ~(0x80 << (8 * (buffer.length - 1))));
    }

    return result;
  }

  static encode(num) {
    if (num === 0) return Buffer.alloc(0);

    const negative = num < 0;
    let absValue = Math.abs(num);
    const result = [];

    while (absValue > 0) {
      result.push(absValue & 0xff);
      absValue >>= 8;
    }

    if (result[result.length - 1] & 0x80) {
      result.push(negative ? 0x80 : 0x00);
    } else if (negative) {
      result[result.length - 1] |= 0x80;
    }

    return Buffer.from(result);
  }
}

class TapscriptInterpreter {
  constructor() {
    this.schnorrValidator = new Schnorr();
  }

  async execute(script, witness, context = {}) {
    const executionContext = {
      stack: [],
      altStack: [],
      opCount: 0,
      sigOpsCount: 0,
      sigOpsBudget: this._calculateSigOpsBudget(witness),
      conditionStack: [],
      script: Buffer.isBuffer(script) ? script : Buffer.from(script),
      witness: witness || [],
      ...context
    };

    for (const item of executionContext.witness) {
      executionContext.stack.push(item);
    }

    let offset = 0;
    while (offset < executionContext.script.length) {
      const opcode = executionContext.script[offset];
      offset++;

      if (this._isOpSuccess(opcode)) {
        return { success: true, reason: 'OP_SUCCESS' };
      }

      if (opcode >= 0x01 && opcode <= 0x4b) {
        const data = executionContext.script.slice(offset, offset + opcode);
        offset += opcode;
        executionContext.stack.push(data);
        continue;
      }

      await this._executeOpcode(opcode, executionContext, offset);
      this._checkLimits(executionContext);
    }

    return this._evaluateResult(executionContext);
  }

  _calculateSigOpsBudget(witness) {
    const witnessSize = witness.reduce((sum, item) => sum + item.length, 0);
    return TAPSCRIPT_CONSTANTS.BASE_SIGOPS_BUDGET +
           Math.floor(witnessSize / TAPSCRIPT_CONSTANTS.SIGOPS_PER_WITNESS_UNIT);
  }

  _isOpSuccess(opcode) {
    if (opcode === 0x50) return true;
    if (opcode === 0x62) return true;
    if (opcode === 0x89) return true;
    if (opcode === 0x8a) return true;
    if (opcode >= 0x8d && opcode <= 0x8e) return true;
    if (opcode >= 0x95 && opcode <= 0x99) return true;
    if (opcode >= 0xbb && opcode <= 0xfe) return true;
    return false;
  }

  async _executeOpcode(opcode, context) {
    context.opCount++;

    switch (opcode) {
      case OPCODES.OP_0:
        context.stack.push(Buffer.alloc(0));
        break;

      case OPCODES.OP_DUP:
        if (context.stack.length < 1) {
          throw new TapscriptError('Stack underflow', 'STACK_UNDERFLOW');
        }
        context.stack.push(Buffer.from(context.stack[context.stack.length - 1]));
        break;

      case OPCODES.OP_EQUAL:
        this._executeEqual(context);
        break;

      case OPCODES.OP_EQUALVERIFY:
        this._executeEqual(context);
        if (!this._isTruthy(context.stack.pop())) {
          throw new TapscriptError('EQUALVERIFY failed', 'VERIFY_FAILED');
        }
        break;

      case OPCODES.OP_VERIFY:
        if (context.stack.length < 1) {
          throw new TapscriptError('Stack underflow', 'STACK_UNDERFLOW');
        }
        if (!this._isTruthy(context.stack.pop())) {
          throw new TapscriptError('VERIFY failed', 'VERIFY_FAILED');
        }
        break;

      case OPCODES.OP_CHECKSIG:
        await this._executeChecksig(context, context.sigHash);
        break;

      case OPCODES.OP_CHECKSIGVERIFY:
        await this._executeChecksig(context, context.sigHash);
        if (!this._isTruthy(context.stack.pop())) {
          throw new TapscriptError('CHECKSIGVERIFY failed', 'VERIFY_FAILED');
        }
        break;

      case OPCODES.OP_CHECKSIGADD:
        await this._executeChecksigAdd(context, context.sigHash);
        break;

      default:
        if (opcode >= OPCODES.OP_1 && opcode <= OPCODES.OP_16) {
          context.stack.push(Buffer.from([opcode - OPCODES.OP_1 + 1]));
        }
    }
  }

  _executeEqual(context) {
    if (context.stack.length < 2) {
      throw new TapscriptError('Stack underflow', 'STACK_UNDERFLOW');
    }
    const b = context.stack.pop();
    const a = context.stack.pop();
    context.stack.push(a.equals(b) ? Buffer.from([0x01]) : Buffer.alloc(0));
  }

  async _executeChecksig(context, sigHash) {
    if (context.stack.length < 2) {
      throw new TapscriptError('Stack underflow', 'STACK_UNDERFLOW');
    }

    const pubkey = context.stack.pop();
    const signature = context.stack.pop();

    context.sigOpsCount++;
    this._checkBudgets(context);

    if (signature.length === 0) {
      context.stack.push(Buffer.alloc(0));
      return;
    }

    if (signature.length !== 64 || pubkey.length !== 32) {
      context.stack.push(Buffer.alloc(0));
      return;
    }

    try {
      const isValid = await this.schnorrValidator.verify(signature, sigHash, pubkey);
      context.stack.push(isValid ? Buffer.from([0x01]) : Buffer.alloc(0));
    } catch {
      context.stack.push(Buffer.alloc(0));
    }
  }

  async _executeChecksigAdd(context, sigHash) {
    if (context.stack.length < 3) {
      throw new TapscriptError('Stack underflow', 'STACK_UNDERFLOW');
    }

    const pubkey = context.stack.pop();
    const num = context.stack.pop();
    const signature = context.stack.pop();

    context.sigOpsCount++;
    this._checkBudgets(context);

    let n = ScriptNum.decode(num);
    let isValid = false;

    if (signature.length !== 0 && signature.length === 64 && pubkey.length === 32) {
      try {
        isValid = await this.schnorrValidator.verify(signature, sigHash, pubkey);
      } catch {
        isValid = false;
      }
    }

    const result = n + (isValid ? 1 : 0);
    context.stack.push(ScriptNum.encode(result));
  }

  _checkLimits(context) {
    if (context.stack.length > TAPSCRIPT_CONSTANTS.MAX_STACK_SIZE) {
      throw new TapscriptError('Stack size exceeded', 'STACK_OVERFLOW');
    }

    if (context.opCount > TAPSCRIPT_CONSTANTS.MAX_OPS_PER_SCRIPT) {
      throw new TapscriptError('Op count exceeded', 'OP_COUNT_EXCEEDED');
    }
  }

  _checkBudgets(context) {
    if (context.sigOpsCount > context.sigOpsBudget) {
      throw new TapscriptError('Signature operations budget exceeded', 'SIGOPS_EXCEEDED');
    }
  }

  _isTruthy(value) {
    if (!value || value.length === 0) return false;
    for (let i = 0; i < value.length; i++) {
      if (value[i] !== 0) {
        if (i === value.length - 1 && value[i] === 0x80) continue;
        return true;
      }
    }
    return false;
  }

  _evaluateResult(context) {
    if (context.stack.length === 0) {
      return { success: false, reason: 'Empty stack' };
    }

    const topElement = context.stack[context.stack.length - 1];
    return {
      success: this._isTruthy(topElement),
      stack: context.stack,
      opCount: context.opCount,
      sigOpsCount: context.sigOpsCount
    };
  }
}

export {
  TapscriptInterpreter,
  TapscriptError,
  TAPSCRIPT_CONSTANTS,
  OPCODES,
  ScriptNum
};
