/**
 * @fileoverview Threshold signature module exports
 * @description Exports all threshold signature components for use in the J-Bitcoin library.
 *              Implements the nChain Threshold Signatures whitepaper protocol.
 * @version 1.0.0
 * @author yfbsei
 * @license ISC
 */

// Core polynomial operations
export { Polynomial, PolynomialError, generateSecureRandom, CURVE_ORDER } from './polynomial.js';

// Participant management
export { Participant, ParticipantError } from './participant.js';

// Joint Verifiable Random Secret Sharing
export { JVRSS, JVRSSError, runJVRSS } from './jvrss.js';

// Multi-Party Computation operations
export {
    ADDSS,
    PROSS,
    INVSS,
    computeAdditiveShares,
    computeMultiplicativeShares,
    generateEphemeralKeyShares,
    MPCError
} from './mpc-operations.js';

// Main Threshold Signature Scheme
export {
    ThresholdSignatureScheme,
    ThresholdSignatureError,
    createThresholdScheme
} from './threshold-signature.js';

// Default export: the main scheme
export { ThresholdSignatureScheme as default } from './threshold-signature.js';

