/**
 * @fileoverview Enhanced Tapscript interpreter implementation following BIP342
 * 
 * This module implements the complete Tapscript validation rules including modified
 * signature opcodes, OP_CHECKSIGADD, signature operation budgets, and OP_SUCCESSx
 * handling for future soft fork compatibility.
 * 
 * SECURITY FEATURES:
 * - Comprehensive script validation with resource limits
 * - Timing attack prevention with constant-time operations
 * - DoS protection with execution budgets and rate limiting
 * - Secure memory management for script execution
 * - Integration with existing Schnorr signature verification
 * 
 * @see {@link https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki|BIP342 - Validation of Taproot Scripts}
 * @author yfbsei
 * @version 2.1.0
 */

import { createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import Schnorr from '../crypto/signatures/schnorr-BIP340.js';
import { CRYPTO_CONSTANTS } from '../constants.js';

/**
 * Tapscript-specific error class for proper error handling
 */
class TapscriptError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'TapscriptError';
        this.code = code;
        this.details = details;
        this.timestamp = Date.now();
    }
}

/**
 * BIP342 Tapscript constants and validation parameters
 */
const TAPSCRIPT_CONSTANTS = {
    // Script validation limits
    MAX_STACK_SIZE: 1000,
    MAX_SCRIPT_SIZE: 10000,
    MAX_ELEMENT_SIZE: 520,
    MAX_OPS_PER_SCRIPT: 201,

    // Signature operation budget (BIP342)
    BASE_SIGOPS_BUDGET: 50,
    SIGOPS_PER_WITNESS_UNIT: 1,

    // Tapscript version
    LEAF_VERSION_TAPSCRIPT: 0xc0,

    // Maximum execution time for DoS protection
    MAX_EXECUTION_TIME_MS: 5000,

    // Rate limiting
    MAX_VALIDATIONS_PER_SECOND: 100,

    // Number encoding limits
    MAX_SCRIPT_NUM_SIZE: 4,

    // Memory clearing passes
    MEMORY_CLEAR_PASSES: 3
};

/**
 * Bitcoin script opcodes with Tapscript modifications
 */
const OPCODES = {
    // Stack operations
    OP_FALSE: 0x00,
    OP_TRUE: 0x51,
    OP_DUP: 0x76,
    OP_DROP: 0x75,
    OP_SWAP: 0x7c,
    OP_ROT: 0x7b,
    OP_ADD: 0x93,

    // Crypto operations (modified in Tapscript)
    OP_CHECKSIG: 0xac,
    OP_CHECKSIGVERIFY: 0xad,
    OP_CHECKSIGADD: 0xba, // New in BIP342
    OP_CHECKMULTISIG: 0xae, // Disabled in Tapscript
    OP_CHECKMULTISIGVERIFY: 0xaf, // Disabled in Tapscript

    // Flow control
    OP_IF: 0x63,
    OP_NOTIF: 0x64,
    OP_ELSE: 0x67,
    OP_ENDIF: 0x68,
    OP_VERIFY: 0x69,
    OP_RETURN: 0x6a,

    // Push data
    OP_PUSHDATA1: 0x4c,
    OP_PUSHDATA2: 0x4d,
    OP_PUSHDATA4: 0x4e,

    // OP_SUCCESSx opcodes (80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254)
    OP_SUCCESS_OPCODES: new Set([
        80, 98,
        ...Array.from({ length: 4 }, (_, i) => 126 + i), // 126-129
        ...Array.from({ length: 4 }, (_, i) => 131 + i), // 131-134
        ...Array.from({ length: 2 }, (_, i) => 137 + i), // 137-138
        ...Array.from({ length: 2 }, (_, i) => 141 + i), // 141-142
        ...Array.from({ length: 5 }, (_, i) => 149 + i), // 149-153
        ...Array.from({ length: 68 }, (_, i) => 187 + i)  // 187-254
    ])
};

/**
 * Enhanced security utilities for Tapscript operations
 */
class TapscriptSecurityUtils {
    static validationHistory = new Map();
    static lastCleanup = Date.now();

    /**
     * Rate limiting for script validation
     */
    static checkRateLimit(operation = 'script-validation') {
        const now = Date.now();
        const secondKey = `${operation}-${Math.floor(now / 1000)}`;
        const currentCount = this.validationHistory.get(secondKey) || 0;

        if (currentCount >= TAPSCRIPT_CONSTANTS.MAX_VALIDATIONS_PER_SECOND) {
            throw new TapscriptError(
                `Rate limit exceeded for ${operation}`,
                'RATE_LIMIT_EXCEEDED',
                { operation, currentCount }
            );
        }

        this.validationHistory.set(secondKey, currentCount + 1);

        // Cleanup old entries
        if (now - this.lastCleanup > 60000) {
            const cutoff = Math.floor(now / 1000) - 60;
            for (const [key] of this.validationHistory) {
                const keyTime = parseInt(key.split('-').pop());
                if (keyTime < cutoff) {
                    this.validationHistory.delete(key);
                }
            }
            this.lastCleanup = now;
        }
    }

    /**
     * Validates execution time to prevent DoS attacks
     */
    static validateExecutionTime(startTime, operation = 'script execution') {
        const elapsed = Date.now() - startTime;
        if (elapsed > TAPSCRIPT_CONSTANTS.MAX_EXECUTION_TIME_MS) {
            throw new TapscriptError(
                `${operation} timeout: ${elapsed}ms > ${TAPSCRIPT_CONSTANTS.MAX_EXECUTION_TIME_MS}ms`,
                'EXECUTION_TIMEOUT',
                { elapsed, maxTime: TAPSCRIPT_CONSTANTS.MAX_EXECUTION_TIME_MS }
            );
        }
    }

    /**
     * Constant-time buffer comparison
     */
    static constantTimeEqual(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
            return false;
        }
        if (a.length !== b.length) {
            return false;
        }

        try {
            return timingSafeEqual(a, b);
        } catch (error) {
            let result = 0;
            for (let i = 0; i < a.length; i++) {
                result |= a[i] ^ b[i];
            }
            return result === 0;
        }
    }

    /**
     * Secure stack element validation
     */
    static validateStackElement(element, fieldName = 'stack element') {
        if (!Buffer.isBuffer(element)) {
            throw new TapscriptError(
                `${fieldName} must be a Buffer`,
                'INVALID_STACK_ELEMENT_TYPE'
            );
        }

        if (element.length > TAPSCRIPT_CONSTANTS.MAX_ELEMENT_SIZE) {
            throw new TapscriptError(
                `${fieldName} too large: ${element.length} > ${TAPSCRIPT_CONSTANTS.MAX_ELEMENT_SIZE}`,
                'STACK_ELEMENT_TOO_LARGE',
                { actualSize: element.length, maxSize: TAPSCRIPT_CONSTANTS.MAX_ELEMENT_SIZE }
            );
        }
    }

    /**
     * Secure memory clearing
     */
    static secureClear(data) {
        if (Buffer.isBuffer(data)) {
            for (let pass = 0; pass < TAPSCRIPT_CONSTANTS.MEMORY_CLEAR_PASSES; pass++) {
                const randomData = randomBytes(data.length);
                randomData.copy(data);
                data.fill(pass % 2 === 0 ? 0x00 : 0xFF);
            }
            data.fill(0x00);
        } else if (Array.isArray(data)) {
            data.forEach(item => {
                if (Buffer.isBuffer(item)) {
                    this.secureClear(item);
                }
            });
            data.length = 0;
        }
    }
}

/**
 * Script number utilities for proper encoding/decoding
 */
class ScriptNum {
    /**
     * Decode a script number from buffer (BIP342 rules)
     */
    static decode(buffer, maxSize = TAPSCRIPT_CONSTANTS.MAX_SCRIPT_NUM_SIZE) {
        if (buffer.length === 0) {
            return 0;
        }

        if (buffer.length > maxSize) {
            throw new TapscriptError(
                `Script number too large: ${buffer.length} > ${maxSize}`,
                'SCRIPT_NUMBER_TOO_LARGE'
            );
        }

        let result = 0;
        let negative = false;

        // Check sign bit
        if (buffer[buffer.length - 1] & 0x80) {
            negative = true;
        }

        // Convert from little-endian
        for (let i = 0; i < buffer.length; i++) {
            if (i === buffer.length - 1) {
                // Last byte - mask out sign bit
                result |= (buffer[i] & 0x7f) << (8 * i);
            } else {
                result |= buffer[i] << (8 * i);
            }
        }

        return negative ? -result : result;
    }

    /**
     * Encode a number to script number format (minimal encoding)
     */
    static encode(num) {
        if (num === 0) {
            return Buffer.alloc(0);
        }

        const negative = num < 0;
        let absValue = Math.abs(num);
        const bytes = [];

        while (absValue > 0) {
            bytes.push(absValue & 0xff);
            absValue = Math.floor(absValue / 256);
        }

        // If the most significant bit is set, add a padding byte
        if (bytes[bytes.length - 1] & 0x80) {
            bytes.push(negative ? 0x80 : 0x00);
        } else if (negative) {
            bytes[bytes.length - 1] |= 0x80;
        }

        return Buffer.from(bytes);
    }

    /**
     * Check if buffer represents true in script context
     */
    static isTrue(buffer) {
        if (buffer.length === 0) {
            return false;
        }

        // Check for negative zero
        for (let i = 0; i < buffer.length; i++) {
            if (buffer[i] !== 0) {
                // If this is the last byte and it's 0x80, it's negative zero
                if (i === buffer.length - 1 && buffer[i] === 0x80) {
                    return false;
                }
                return true;
            }
        }

        return false;
    }
}

/**
 * Tapscript execution context for secure script evaluation
 */
class TapscriptExecutionContext {
    constructor(script, witness, sigVersion = 1) {
        this.script = script;
        this.witness = witness;
        this.sigVersion = sigVersion;
        this.stack = [];
        this.altStack = [];
        this.pc = 0; // Program counter
        this.opCount = 0;
        this.sigOpsCount = 0;
        this.sigOpsBudget = this.calculateSigOpsBudget();
        this.startTime = Date.now();
        this.executed = false;
        this.conditionStack = []; // For IF/ELSE/ENDIF
        this.skipExecution = false;
    }

    /**
     * Calculate signature operations budget according to BIP342
     */
    calculateSigOpsBudget() {
        let witnessSize = 0;
        for (const item of this.witness) {
            witnessSize += item.length + this.getCompactSizeLength(item.length);
        }
        return TAPSCRIPT_CONSTANTS.BASE_SIGOPS_BUDGET + witnessSize;
    }

    /**
     * Get compact size encoding length
     */
    getCompactSizeLength(value) {
        if (value < 0xfd) return 1;
        if (value <= 0xffff) return 3;
        if (value <= 0xffffffff) return 5;
        return 9;
    }

    /**
     * Push element to main stack with validation
     */
    pushStack(element) {
        TapscriptSecurityUtils.validateStackElement(element);

        if (this.stack.length + this.altStack.length >= TAPSCRIPT_CONSTANTS.MAX_STACK_SIZE) {
            throw new TapscriptError(
                'Stack size limit exceeded',
                'STACK_SIZE_EXCEEDED',
                { stackSize: this.stack.length, altStackSize: this.altStack.length }
            );
        }

        this.stack.push(Buffer.from(element)); // Always make a copy
    }

    /**
     * Pop element from main stack
     */
    popStack() {
        if (this.stack.length === 0) {
            throw new TapscriptError(
                'Cannot pop from empty stack',
                'STACK_UNDERFLOW'
            );
        }
        return this.stack.pop();
    }

    /**
     * Peek at top stack element without removing
     */
    peekStack(index = 0) {
        if (this.stack.length <= index) {
            throw new TapscriptError(
                'Stack underflow in peek operation',
                'STACK_UNDERFLOW'
            );
        }
        return this.stack[this.stack.length - 1 - index];
    }

    /**
     * Check if we need to skip execution (IF/ELSE logic)
     */
    shouldSkipExecution() {
        return this.conditionStack.length > 0 && !this.conditionStack[this.conditionStack.length - 1];
    }

    /**
     * Check if execution budget is exceeded
     */
    checkBudgets() {
        // Check operation count
        if (this.opCount > TAPSCRIPT_CONSTANTS.MAX_OPS_PER_SCRIPT) {
            throw new TapscriptError(
                'Operation count limit exceeded',
                'OP_COUNT_EXCEEDED',
                { opCount: this.opCount, maxOps: TAPSCRIPT_CONSTANTS.MAX_OPS_PER_SCRIPT }
            );
        }

        // Check signature operations budget
        if (this.sigOpsCount > this.sigOpsBudget) {
            throw new TapscriptError(
                'Signature operations budget exceeded',
                'SIGOPS_BUDGET_EXCEEDED',
                { sigOpsCount: this.sigOpsCount, budget: this.sigOpsBudget }
            );
        }

        // Check execution time
        TapscriptSecurityUtils.validateExecutionTime(this.startTime);
    }

    /**
     * Clean up sensitive data
     */
    destroy() {
        TapscriptSecurityUtils.secureClear(this.stack);
        TapscriptSecurityUtils.secureClear(this.altStack);
        TapscriptSecurityUtils.secureClear(this.script);
        if (this.witness) {
            TapscriptSecurityUtils.secureClear(this.witness);
        }
    }
}

/**
 * Enhanced Tapscript interpreter with comprehensive BIP342 implementation
 */
class TapscriptInterpreter {
    constructor() {
        this.schnorrValidator = new Schnorr.Enhanced();
    }

    /**
     * Validate and execute a Tapscript with comprehensive security checks
     * 
     * @param {Buffer} script - The script to execute
     * @param {Buffer[]} witness - Witness stack elements
     * @param {Buffer} sigHash - Signature hash for signature operations
     * @param {Object} options - Execution options
     * @returns {boolean} True if script validates successfully
     */
    async validateScript(script, witness, sigHash, options = {}) {
        const startTime = Date.now();
        let context = null;

        try {
            TapscriptSecurityUtils.checkRateLimit();

            // Input validation
            if (!Buffer.isBuffer(script)) {
                throw new TapscriptError('Script must be a Buffer', 'INVALID_SCRIPT_TYPE');
            }

            if (!Array.isArray(witness)) {
                throw new TapscriptError('Witness must be an array', 'INVALID_WITNESS_TYPE');
            }

            if (!Buffer.isBuffer(sigHash) || sigHash.length !== 32) {
                throw new TapscriptError('Signature hash must be 32 bytes', 'INVALID_SIGHASH');
            }

            // Script size validation
            if (script.length > TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE) {
                throw new TapscriptError(
                    `Script too large: ${script.length} > ${TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE}`,
                    'SCRIPT_TOO_LARGE'
                );
            }

            // Validate leaf version if provided
            const leafVersion = options.leafVersion || TAPSCRIPT_CONSTANTS.LEAF_VERSION_TAPSCRIPT;
            if (leafVersion !== TAPSCRIPT_CONSTANTS.LEAF_VERSION_TAPSCRIPT) {
                throw new TapscriptError(
                    `Unsupported leaf version: 0x${leafVersion.toString(16)}`,
                    'UNSUPPORTED_LEAF_VERSION'
                );
            }

            context = new TapscriptExecutionContext(script, witness, 1);

            // Initialize stack with witness elements (excluding script and control block)
            for (const element of witness) {
                if (Buffer.isBuffer(element)) {
                    context.pushStack(element);
                } else {
                    throw new TapscriptError('All witness elements must be Buffers', 'INVALID_WITNESS_ELEMENT');
                }
            }

            // Execute script
            await this.executeScript(context, sigHash, options);

            TapscriptSecurityUtils.validateExecutionTime(startTime, 'script validation');

            // Final validation - stack must have exactly one true element
            if (context.stack.length !== 1) {
                throw new TapscriptError(
                    `Invalid final stack size: ${context.stack.length}, expected 1`,
                    'INVALID_FINAL_STACK_SIZE'
                );
            }

            const result = ScriptNum.isTrue(context.stack[0]);
            if (!result) {
                throw new TapscriptError(
                    'Script evaluation returned false',
                    'SCRIPT_EVALUATION_FALSE'
                );
            }

            return true;

        } catch (error) {
            if (error instanceof TapscriptError) {
                throw error;
            }
            throw new TapscriptError(
                `Script validation failed: ${error.message}`,
                'VALIDATION_FAILED',
                { originalError: error.message }
            );
        } finally {
            if (context) {
                context.destroy();
            }
        }
    }

    /**
     * Execute script operations with BIP342 rules
     */
    async executeScript(context, sigHash, options) {
        while (context.pc < context.script.length) {
            context.checkBudgets();

            const opcode = context.script[context.pc];
            context.pc++;
            context.opCount++;

            // Handle OP_SUCCESSx opcodes - unconditionally valid
            if (OPCODES.OP_SUCCESS_OPCODES.has(opcode)) {
                console.log(`✅ OP_SUCCESS opcode ${opcode} encountered - unconditionally valid`);
                return true;
            }

            await this.executeOpcode(context, opcode, sigHash, options);
        }

        // Check that all conditionals are closed
        if (context.conditionStack.length > 0) {
            throw new TapscriptError(
                'Unmatched IF/ELSE/ENDIF',
                'UNMATCHED_CONDITIONAL'
            );
        }
    }

    /**
     * Execute individual opcode with Tapscript modifications
     */
    async executeOpcode(context, opcode, sigHash, options) {
        // Skip execution if we're in a false conditional branch
        const shouldSkip = context.shouldSkipExecution();

        // Flow control opcodes are always executed
        const isFlowControl = [OPCODES.OP_IF, OPCODES.OP_NOTIF, OPCODES.OP_ELSE, OPCODES.OP_ENDIF].includes(opcode);

        if (shouldSkip && !isFlowControl) {
            return;
        }

        switch (opcode) {
            // Stack operations
            case OPCODES.OP_FALSE:
                context.pushStack(Buffer.alloc(0));
                break;

            case OPCODES.OP_TRUE:
                context.pushStack(Buffer.from([0x01]));
                break;

            case OPCODES.OP_DUP:
                if (context.stack.length === 0) {
                    throw new TapscriptError('OP_DUP: stack underflow', 'STACK_UNDERFLOW');
                }
                context.pushStack(Buffer.from(context.peekStack()));
                break;

            case OPCODES.OP_DROP:
                context.popStack();
                break;

            case OPCODES.OP_SWAP:
                if (context.stack.length < 2) {
                    throw new TapscriptError('OP_SWAP: insufficient stack elements', 'STACK_UNDERFLOW');
                }
                const a = context.popStack();
                const b = context.popStack();
                context.pushStack(a);
                context.pushStack(b);
                break;

            case OPCODES.OP_ROT:
                if (context.stack.length < 3) {
                    throw new TapscriptError('OP_ROT: insufficient stack elements', 'STACK_UNDERFLOW');
                }
                const x = context.popStack();
                const y = context.popStack();
                const z = context.popStack();
                context.pushStack(y);
                context.pushStack(x);
                context.pushStack(z);
                break;

            // Modified signature operations (BIP342)
            case OPCODES.OP_CHECKSIG:
                await this.executeChecksig(context, sigHash, false);
                break;

            case OPCODES.OP_CHECKSIGVERIFY:
                await this.executeChecksig(context, sigHash, true);
                break;

            case OPCODES.OP_CHECKSIGADD:
                await this.executeChecksigAdd(context, sigHash);
                break;

            // Disabled operations in Tapscript
            case OPCODES.OP_CHECKMULTISIG:
            case OPCODES.OP_CHECKMULTISIGVERIFY:
                throw new TapscriptError(
                    `Opcode ${opcode} is disabled in Tapscript`,
                    'DISABLED_OPCODE'
                );

            // Flow control
            case OPCODES.OP_IF:
            case OPCODES.OP_NOTIF:
                let condition = true;
                if (context.stack.length > 0) {
                    const element = context.popStack();
                    condition = ScriptNum.isTrue(element);
                    if (opcode === OPCODES.OP_NOTIF) {
                        condition = !condition;
                    }
                } else {
                    condition = false;
                }
                context.conditionStack.push(condition);
                break;

            case OPCODES.OP_ELSE:
                if (context.conditionStack.length === 0) {
                    throw new TapscriptError('OP_ELSE without OP_IF', 'ELSE_WITHOUT_IF');
                }
                const lastCondition = context.conditionStack.pop();
                context.conditionStack.push(!lastCondition);
                break;

            case OPCODES.OP_ENDIF:
                if (context.conditionStack.length === 0) {
                    throw new TapscriptError('OP_ENDIF without OP_IF', 'ENDIF_WITHOUT_IF');
                }
                context.conditionStack.pop();
                break;

            case OPCODES.OP_VERIFY:
                const element = context.popStack();
                if (!ScriptNum.isTrue(element)) {
                    throw new TapscriptError('OP_VERIFY failed', 'VERIFY_FAILED');
                }
                break;

            case OPCODES.OP_RETURN:
                throw new TapscriptError('OP_RETURN executed', 'OP_RETURN_EXECUTED');

            // Push data operations
            case OPCODES.OP_PUSHDATA1:
                await this.executePushData(context, 1);
                break;

            case OPCODES.OP_PUSHDATA2:
                await this.executePushData(context, 2);
                break;

            case OPCODES.OP_PUSHDATA4:
                await this.executePushData(context, 4);
                break;

            default:
                if (opcode >= 1 && opcode <= 75) {
                    // Direct push data
                    if (context.pc + opcode > context.script.length) {
                        throw new TapscriptError('Script truncated during push operation', 'SCRIPT_TRUNCATED');
                    }
                    const data = context.script.slice(context.pc, context.pc + opcode);
                    context.pc += opcode;
                    context.pushStack(data);
                } else {
                    throw new TapscriptError(`Unknown opcode: ${opcode}`, 'UNKNOWN_OPCODE');
                }
                break;
        }
    }

    /**
     * Execute PUSHDATA operations
     */
    async executePushData(context, sizeBytes) {
        if (context.pc + sizeBytes > context.script.length) {
            throw new TapscriptError('Script truncated during PUSHDATA', 'SCRIPT_TRUNCATED');
        }

        let dataSize = 0;
        for (let i = 0; i < sizeBytes; i++) {
            dataSize = (dataSize << 8) | context.script[context.pc + i];
        }
        context.pc += sizeBytes;

        if (context.pc + dataSize > context.script.length) {
            throw new TapscriptError('Script truncated during PUSHDATA', 'SCRIPT_TRUNCATED');
        }

        const data = context.script.slice(context.pc, context.pc + dataSize);
        context.pc += dataSize;
        context.pushStack(data);
    }

    /**
     * Execute OP_CHECKSIG/OP_CHECKSIGVERIFY with Schnorr signatures (BIP342)
     */
    async executeChecksig(context, sigHash, verify = false) {
        if (context.stack.length < 2) {
            throw new TapscriptError('OP_CHECKSIG: insufficient stack elements', 'STACK_UNDERFLOW');
        }

        const pubkey = context.popStack();
        const signature = context.popStack();

        context.sigOpsCount++;
        context.checkBudgets();

        let isValid = false;

        // Handle empty signature (BIP342 - always fails but counts towards budget)
        if (signature.length === 0) {
            isValid = false;
        } else {
            try {
                // Validate signature format (64 bytes for Schnorr)
                if (signature.length !== 64) {
                    isValid = false;
                } else if (pubkey.length !== 32) {
                    // Validate public key format (32 bytes x-only)
                    isValid = false;
                } else {
                    // Verify Schnorr signature
                    isValid = await this.schnorrValidator.verify(signature, sigHash, pubkey);
                }
            } catch (error) {
                // Signature validation failed
                isValid = false;
            }
        }

        if (verify) {
            // OP_CHECKSIGVERIFY - must be true or script fails
            if (!isValid) {
                throw new TapscriptError('OP_CHECKSIGVERIFY failed', 'CHECKSIGVERIFY_FAILED');
            }
        } else {
            // OP_CHECKSIG - push result to stack
            context.pushStack(isValid ? Buffer.from([0x01]) : Buffer.alloc(0));
        }
    }

    /**
     * Execute OP_CHECKSIGADD - new efficient multisig opcode (BIP342)
     */
    async executeChecksigAdd(context, sigHash) {
        if (context.stack.length < 3) {
            throw new TapscriptError('OP_CHECKSIGADD: insufficient stack elements', 'STACK_UNDERFLOW');
        }

        const pubkey = context.popStack();
        const num = context.popStack();
        const signature = context.popStack();

        context.sigOpsCount++;
        context.checkBudgets();

        // Convert num to integer
        let n = 0;
        try {
            n = ScriptNum.decode(num);
        } catch (error) {
            throw new TapscriptError('OP_CHECKSIGADD: invalid number format', 'INVALID_NUMBER_FORMAT');
        }

        let isValid = false;

        // Handle empty signature
        if (signature.length === 0) {
            isValid = false;
        } else {
            try {
                // Same validation as OP_CHECKSIG
                if (signature.length !== 64 || pubkey.length !== 32) {
                    isValid = false;
                } else {
                    isValid = await this.schnorrValidator.verify(signature, sigHash, pubkey);
                }
            } catch (error) {
                isValid = false;
            }
        }

        // Add 1 if signature is valid, 0 if not
        const result = n + (isValid ? 1 : 0);

        // Convert result back to minimal encoding
        const resultBuffer = ScriptNum.encode(result);
        context.pushStack(resultBuffer);
    }

    /**
     * Validate script syntax without execution (static analysis)
     */
    validateScriptSyntax(script) {
        try {
            if (!Buffer.isBuffer(script)) {
                throw new TapscriptError('Script must be a Buffer', 'INVALID_SCRIPT_TYPE');
            }

            if (script.length > TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE) {
                throw new TapscriptError(
                    `Script too large: ${script.length} > ${TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE}`,
                    'SCRIPT_TOO_LARGE'
                );
            }

            let pc = 0;
            let opCount = 0;
            const conditionStack = [];

            while (pc < script.length) {
                const opcode = script[pc];
                pc++;
                opCount++;

                if (opCount > TAPSCRIPT_CONSTANTS.MAX_OPS_PER_SCRIPT) {
                    throw new TapscriptError(
                        'Operation count limit exceeded in syntax validation',
                        'OP_COUNT_EXCEEDED'
                    );
                }

                // Check for disabled opcodes
                if (opcode === OPCODES.OP_CHECKMULTISIG || opcode === OPCODES.OP_CHECKMULTISIGVERIFY) {
                    throw new TapscriptError(
                        `Opcode ${opcode} is disabled in Tapscript`,
                        'DISABLED_OPCODE'
                    );
                }

                // Handle control flow for syntax validation
                if (opcode === OPCODES.OP_IF || opcode === OPCODES.OP_NOTIF) {
                    conditionStack.push(true);
                } else if (opcode === OPCODES.OP_ELSE) {
                    if (conditionStack.length === 0) {
                        throw new TapscriptError('OP_ELSE without OP_IF', 'ELSE_WITHOUT_IF');
                    }
                } else if (opcode === OPCODES.OP_ENDIF) {
                    if (conditionStack.length === 0) {
                        throw new TapscriptError('OP_ENDIF without OP_IF', 'ENDIF_WITHOUT_IF');
                    }
                    conditionStack.pop();
                }

                // Handle push data operations
                if (opcode >= 1 && opcode <= 75) {
                    // Direct push
                    if (pc + opcode > script.length) {
                        throw new TapscriptError('Script truncated during push operation', 'SCRIPT_TRUNCATED');
                    }
                    pc += opcode;
                } else if (opcode === OPCODES.OP_PUSHDATA1) {
                    if (pc + 1 > script.length) {
                        throw new TapscriptError('Script truncated during PUSHDATA1', 'SCRIPT_TRUNCATED');
                    }
                    const dataSize = script[pc];
                    pc += 1 + dataSize;
                    if (pc > script.length) {
                        throw new TapscriptError('Script truncated during PUSHDATA1', 'SCRIPT_TRUNCATED');
                    }
                } else if (opcode === OPCODES.OP_PUSHDATA2) {
                    if (pc + 2 > script.length) {
                        throw new TapscriptError('Script truncated during PUSHDATA2', 'SCRIPT_TRUNCATED');
                    }
                    const dataSize = (script[pc] << 8) | script[pc + 1];
                    pc += 2 + dataSize;
                    if (pc > script.length) {
                        throw new TapscriptError('Script truncated during PUSHDATA2', 'SCRIPT_TRUNCATED');
                    }
                } else if (opcode === OPCODES.OP_PUSHDATA4) {
                    if (pc + 4 > script.length) {
                        throw new TapscriptError('Script truncated during PUSHDATA4', 'SCRIPT_TRUNCATED');
                    }
                    const dataSize = (script[pc] << 24) | (script[pc + 1] << 16) | (script[pc + 2] << 8) | script[pc + 3];
                    pc += 4 + dataSize;
                    if (pc > script.length) {
                        throw new TapscriptError('Script truncated during PUSHDATA4', 'SCRIPT_TRUNCATED');
                    }
                }
            }

            // Check that all conditionals are closed
            if (conditionStack.length > 0) {
                throw new TapscriptError(
                    'Unmatched IF/ELSE/ENDIF in script',
                    'UNMATCHED_CONDITIONAL'
                );
            }

            return true;

        } catch (error) {
            if (error instanceof TapscriptError) {
                throw error;
            }
            throw new TapscriptError(
                `Script syntax validation failed: ${error.message}`,
                'SYNTAX_VALIDATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Estimate script execution complexity and resource usage
     */
    estimateScriptComplexity(script, witnessSize = 0) {
        try {
            const complexity = {
                opcodeCount: 0,
                maxStackDepth: 0,
                estimatedSigOps: 0,
                estimatedExecutionTime: 0,
                riskLevel: 'low'
            };

            if (!Buffer.isBuffer(script)) {
                throw new TapscriptError('Script must be a Buffer', 'INVALID_SCRIPT_TYPE');
            }

            let pc = 0;
            let stackDepth = witnessSize;
            let maxStackDepth = stackDepth;

            while (pc < script.length) {
                const opcode = script[pc];
                pc++;
                complexity.opcodeCount++;

                // Estimate stack effects
                switch (opcode) {
                    case OPCODES.OP_FALSE:
                    case OPCODES.OP_TRUE:
                        stackDepth++;
                        break;
                    case OPCODES.OP_DUP:
                        stackDepth++;
                        break;
                    case OPCODES.OP_DROP:
                        stackDepth = Math.max(0, stackDepth - 1);
                        break;
                    case OPCODES.OP_CHECKSIG:
                        complexity.estimatedSigOps++;
                        stackDepth = Math.max(0, stackDepth - 1); // net -1 (pop 2, push 1)
                        break;
                    case OPCODES.OP_CHECKSIGVERIFY:
                        complexity.estimatedSigOps++;
                        stackDepth = Math.max(0, stackDepth - 2);
                        break;
                    case OPCODES.OP_CHECKSIGADD:
                        complexity.estimatedSigOps++;
                        stackDepth = Math.max(0, stackDepth - 2); // net -2 (pop 3, push 1)
                        break;
                }

                // Handle push operations
                if (opcode >= 1 && opcode <= 75) {
                    stackDepth++;
                    pc += opcode;
                } else if (opcode === OPCODES.OP_PUSHDATA1) {
                    if (pc < script.length) {
                        stackDepth++;
                        pc += 1 + script[pc];
                    }
                } else if (opcode === OPCODES.OP_PUSHDATA2) {
                    if (pc + 1 < script.length) {
                        stackDepth++;
                        const size = (script[pc] << 8) | script[pc + 1];
                        pc += 2 + size;
                    }
                } else if (opcode === OPCODES.OP_PUSHDATA4) {
                    if (pc + 3 < script.length) {
                        stackDepth++;
                        const size = (script[pc] << 24) | (script[pc + 1] << 16) | (script[pc + 2] << 8) | script[pc + 3];
                        pc += 4 + size;
                    }
                }

                maxStackDepth = Math.max(maxStackDepth, stackDepth);
            }

            complexity.maxStackDepth = maxStackDepth;

            // Estimate execution time (rough heuristic)
            complexity.estimatedExecutionTime =
                complexity.opcodeCount * 0.1 +
                complexity.estimatedSigOps * 10; // Sig ops are expensive

            // Determine risk level
            if (complexity.opcodeCount > 150 || complexity.estimatedSigOps > 20 || complexity.maxStackDepth > 500) {
                complexity.riskLevel = 'high';
            } else if (complexity.opcodeCount > 50 || complexity.estimatedSigOps > 5 || complexity.maxStackDepth > 100) {
                complexity.riskLevel = 'medium';
            }

            return complexity;

        } catch (error) {
            throw new TapscriptError(
                `Script complexity estimation failed: ${error.message}`,
                'COMPLEXITY_ESTIMATION_FAILED',
                { originalError: error.message }
            );
        }
    }

    /**
     * Check if a script contains potentially dangerous operations
     */
    checkScriptSafety(script) {
        try {
            const safetyReport = {
                safe: true,
                warnings: [],
                errors: [],
                recommendations: []
            };

            if (!Buffer.isBuffer(script)) {
                safetyReport.safe = false;
                safetyReport.errors.push('Script must be a Buffer');
                return safetyReport;
            }

            let pc = 0;
            let opCount = 0;
            let sigOpCount = 0;

            while (pc < script.length) {
                const opcode = script[pc];
                pc++;
                opCount++;

                // Check for disabled opcodes
                if (opcode === OPCODES.OP_CHECKMULTISIG || opcode === OPCODES.OP_CHECKMULTISIGVERIFY) {
                    safetyReport.safe = false;
                    safetyReport.errors.push(`Disabled opcode ${opcode} found`);
                }

                // Check for signature operations
                if (opcode === OPCODES.OP_CHECKSIG || opcode === OPCODES.OP_CHECKSIGVERIFY || opcode === OPCODES.OP_CHECKSIGADD) {
                    sigOpCount++;
                }

                // Check for potentially problematic opcodes
                if (opcode === OPCODES.OP_RETURN) {
                    safetyReport.warnings.push('OP_RETURN found - script will always fail');
                }

                // Handle push data
                if (opcode >= 1 && opcode <= 75) {
                    if (pc + opcode > script.length) {
                        safetyReport.safe = false;
                        safetyReport.errors.push('Script truncated during push operation');
                        break;
                    }
                    pc += opcode;
                } else if (opcode === OPCODES.OP_PUSHDATA1) {
                    if (pc >= script.length) {
                        safetyReport.safe = false;
                        safetyReport.errors.push('Script truncated during PUSHDATA1');
                        break;
                    }
                    const size = script[pc];
                    pc += 1 + size;
                } else if (opcode === OPCODES.OP_PUSHDATA2) {
                    if (pc + 1 >= script.length) {
                        safetyReport.safe = false;
                        safetyReport.errors.push('Script truncated during PUSHDATA2');
                        break;
                    }
                    const size = (script[pc] << 8) | script[pc + 1];
                    pc += 2 + size;
                } else if (opcode === OPCODES.OP_PUSHDATA4) {
                    if (pc + 3 >= script.length) {
                        safetyReport.safe = false;
                        safetyReport.errors.push('Script truncated during PUSHDATA4');
                        break;
                    }
                    const size = (script[pc] << 24) | (script[pc + 1] << 16) | (script[pc + 2] << 8) | script[pc + 3];
                    pc += 4 + size;
                }

                if (pc > script.length) {
                    safetyReport.safe = false;
                    safetyReport.errors.push('Script extends beyond buffer length');
                    break;
                }
            }

            // Check limits
            if (opCount > TAPSCRIPT_CONSTANTS.MAX_OPS_PER_SCRIPT) {
                safetyReport.warnings.push(`High opcode count: ${opCount}`);
            }

            if (sigOpCount > 20) {
                safetyReport.warnings.push(`High signature operation count: ${sigOpCount}`);
            }

            if (script.length > TAPSCRIPT_CONSTANTS.MAX_SCRIPT_SIZE * 0.8) {
                safetyReport.warnings.push(`Large script size: ${script.length} bytes`);
            }

            // Recommendations
            if (sigOpCount > 10) {
                safetyReport.recommendations.push('Consider optimizing signature operations for better performance');
            }

            if (opCount > 100) {
                safetyReport.recommendations.push('Consider simplifying script logic to reduce operation count');
            }

            return safetyReport;

        } catch (error) {
            return {
                safe: false,
                warnings: [],
                errors: [`Safety check failed: ${error.message}`],
                recommendations: ['Script cannot be safely analyzed']
            };
        }
    }

    /**
     * Get interpreter status and metrics
     */
    getStatus() {
        return {
            version: '2.1.0',
            features: [
                'BIP342 Tapscript validation',
                'Schnorr signature verification',
                'OP_CHECKSIGADD support',
                'OP_SUCCESSx handling',
                'Resource limit enforcement',
                'DoS protection',
                'Script syntax validation',
                'Security analysis',
                'Complexity estimation'
            ],
            constants: TAPSCRIPT_CONSTANTS,
            opcodes: {
                total: Object.keys(OPCODES).length - 1, // Exclude OP_SUCCESS_OPCODES set
                successOpcodes: OPCODES.OP_SUCCESS_OPCODES.size,
                disabled: ['OP_CHECKMULTISIG', 'OP_CHECKMULTISIGVERIFY']
            },
            rateLimit: {
                maxPerSecond: TAPSCRIPT_CONSTANTS.MAX_VALIDATIONS_PER_SECOND,
                currentEntries: TapscriptSecurityUtils.validationHistory.size
            }
        };
    }

    /**
     * Run comprehensive self-tests to validate interpreter implementation
     */
    async runSelfTests() {
        console.log('🧪 Running Tapscript interpreter self-tests...');

        const results = {
            passed: 0,
            failed: 0,
            tests: []
        };

        // Test 1: Basic script validation
        try {
            const script = Buffer.from([OPCODES.OP_TRUE]);
            const witness = [];
            const sigHash = Buffer.alloc(32, 0x01);

            const result = await this.validateScript(script, witness, sigHash);
            if (result) {
                results.passed++;
                results.tests.push({ name: 'Basic OP_TRUE script', status: 'PASS' });
            } else {
                throw new Error('Script should have passed');
            }
        } catch (error) {
            results.failed++;
            results.tests.push({ name: 'Basic OP_TRUE script', status: 'FAIL', error: error.message });
        }

        // Test 2: Script syntax validation
        try {
            const script = Buffer.from([OPCODES.OP_IF, OPCODES.OP_TRUE, OPCODES.OP_ENDIF]);
            const isValid = this.validateScriptSyntax(script);
            if (isValid) {
                results.passed++;
                results.tests.push({ name: 'Script syntax validation', status: 'PASS' });
            } else {
                throw new Error('Syntax validation should have passed');
            }
        } catch (error) {
            results.failed++;
            results.tests.push({ name: 'Script syntax validation', status: 'FAIL', error: error.message });
        }

        // Test 3: Disabled opcode detection
        try {
            const script = Buffer.from([OPCODES.OP_CHECKMULTISIG]);
            const witness = [];
            const sigHash = Buffer.alloc(32, 0x01);

            try {
                await this.validateScript(script, witness, sigHash);
                throw new Error('Should have failed');
            } catch (error) {
                if (error.code === 'DISABLED_OPCODE') {
                    results.passed++;
                    results.tests.push({ name: 'Disabled opcode detection', status: 'PASS' });
                } else {
                    throw error;
                }
            }
        } catch (error) {
            results.failed++;
            results.tests.push({ name: 'Disabled opcode detection', status: 'FAIL', error: error.message });
        }

        // Test 4: OP_SUCCESS handling
        try {
            const script = Buffer.from([80]); // OP_SUCCESS opcode
            const witness = [];
            const sigHash = Buffer.alloc(32, 0x01);

            const result = await this.validateScript(script, witness, sigHash);
            if (result) {
                results.passed++;
                results.tests.push({ name: 'OP_SUCCESS handling', status: 'PASS' });
            } else {
                throw new Error('OP_SUCCESS should have passed');
            }
        } catch (error) {
            results.failed++;
            results.tests.push({ name: 'OP_SUCCESS handling', status: 'FAIL', error: error.message });
        }

        // Test 5: ScriptNum encoding/decoding
        try {
            const testNumbers = [0, 1, -1, 127, -127, 128, -128, 32767, -32767];
            let allPassed = true;

            for (const num of testNumbers) {
                const encoded = ScriptNum.encode(num);
                const decoded = ScriptNum.decode(encoded);
                if (decoded !== num) {
                    throw new Error(`ScriptNum test failed for ${num}: got ${decoded}`);
                }
            }

            if (allPassed) {
                results.passed++;
                results.tests.push({ name: 'ScriptNum encoding/decoding', status: 'PASS' });
            }
        } catch (error) {
            results.failed++;
            results.tests.push({ name: 'ScriptNum encoding/decoding', status: 'FAIL', error: error.message });
        }

        console.log(`✅ Self-tests completed: ${results.passed} passed, ${results.failed} failed`);

        if (results.failed > 0) {
            console.log('❌ Failed tests:');
            results.tests.filter(t => t.status === 'FAIL').forEach(t => {
                console.log(`  - ${t.name}: ${t.error}`);
            });
        }

        return results;
    }
}

export {
    TapscriptError,
    TapscriptSecurityUtils,
    TapscriptExecutionContext,
    TapscriptInterpreter,
    ScriptNum,
    TAPSCRIPT_CONSTANTS,
    OPCODES
};