/**
 * @fileoverview Polynomial operations for threshold cryptography
 * @version 2.1.0
 * @author yfbsei
 * @license ISC
 */

import { randomBytes } from 'node:crypto';
import BN from 'bn.js';
import { CRYPTO_CONSTANTS } from '../../../constants.js';

const CURVE_ORDER = new BN(CRYPTO_CONSTANTS.SECP256K1_ORDER, 'hex');

class PolynomialError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'PolynomialError';
    this.code = code;
    this.details = details;
  }
}

function generateSecureRandom(bytes = 32) {
  const buffer = randomBytes(bytes);
  return new BN(buffer).umod(CURVE_ORDER);
}

class Polynomial {
  constructor(degree, secret = null) {
    if (typeof degree !== 'number' || degree < 0) {
      throw new PolynomialError('Degree must be a non-negative integer', 'INVALID_DEGREE');
    }

    this.degree = degree;
    this.coefficients = [];

    if (secret !== null) {
      this.coefficients[0] = secret instanceof BN ? secret : new BN(secret);
    } else {
      this.coefficients[0] = generateSecureRandom();
    }

    for (let i = 1; i <= degree; i++) {
      this.coefficients[i] = generateSecureRandom();
    }
  }

  evaluate(x) {
    if (x === 0 || (x instanceof BN && x.isZero())) {
      throw new PolynomialError('Cannot evaluate at x=0', 'INVALID_X');
    }

    const xBN = x instanceof BN ? x : new BN(x);
    let result = new BN(0);
    let xPower = new BN(1);

    for (let i = 0; i <= this.degree; i++) {
      const term = this.coefficients[i].mul(xPower).umod(CURVE_ORDER);
      result = result.add(term).umod(CURVE_ORDER);
      xPower = xPower.mul(xBN).umod(CURVE_ORDER);
    }

    return result;
  }

  getSecret() {
    return this.coefficients[0].clone();
  }

  getCoefficients() {
    return this.coefficients.map(c => c.clone());
  }

  generateShares(n) {
    if (n <= this.degree) {
      throw new PolynomialError(
        `Need more participants (${n}) than polynomial degree (${this.degree})`,
        'INSUFFICIENT_PARTICIPANTS'
      );
    }

    const shares = [];
    for (let i = 1; i <= n; i++) {
      shares.push({
        x: new BN(i),
        y: this.evaluate(i),
        index: i
      });
    }

    return shares;
  }

  static lagrangeCoefficient(i, xCoords, x = new BN(0)) {
    let numerator = new BN(1);
    let denominator = new BN(1);

    const xi = xCoords[i] instanceof BN ? xCoords[i] : new BN(xCoords[i]);

    for (let j = 0; j < xCoords.length; j++) {
      if (i === j) continue;

      const xj = xCoords[j] instanceof BN ? xCoords[j] : new BN(xCoords[j]);

      numerator = numerator.mul(x.sub(xj)).umod(CURVE_ORDER);
      denominator = denominator.mul(xi.sub(xj)).umod(CURVE_ORDER);
    }

    const denominatorInv = denominator.invm(CURVE_ORDER);
    return numerator.mul(denominatorInv).umod(CURVE_ORDER);
  }

  static interpolate(shares, x = new BN(0)) {
    if (!Array.isArray(shares) || shares.length === 0) {
      throw new PolynomialError('Shares array is required', 'INVALID_SHARES');
    }

    const xCoords = shares.map(s => s.x instanceof BN ? s.x : new BN(s.x));

    let result = new BN(0);

    for (let i = 0; i < shares.length; i++) {
      const yi = shares[i].y instanceof BN ? shares[i].y : new BN(shares[i].y);
      const li = this.lagrangeCoefficient(i, xCoords, x);
      const term = yi.mul(li).umod(CURVE_ORDER);
      result = result.add(term).umod(CURVE_ORDER);
    }

    return result;
  }

  static reconstructSecret(shares) {
    return this.interpolate(shares, new BN(0));
  }

  static add(poly1, poly2) {
    const maxDegree = Math.max(poly1.degree, poly2.degree);
    const result = new Polynomial(maxDegree, new BN(0));

    for (let i = 0; i <= maxDegree; i++) {
      const c1 = i <= poly1.degree ? poly1.coefficients[i] : new BN(0);
      const c2 = i <= poly2.degree ? poly2.coefficients[i] : new BN(0);
      result.coefficients[i] = c1.add(c2).umod(CURVE_ORDER);
    }

    return result;
  }

  static multiply(poly1, poly2) {
    const newDegree = poly1.degree + poly2.degree;
    const result = new Polynomial(newDegree, new BN(0));

    for (let i = 0; i <= newDegree; i++) {
      result.coefficients[i] = new BN(0);
    }

    for (let i = 0; i <= poly1.degree; i++) {
      for (let j = 0; j <= poly2.degree; j++) {
        const term = poly1.coefficients[i].mul(poly2.coefficients[j]).umod(CURVE_ORDER);
        result.coefficients[i + j] = result.coefficients[i + j].add(term).umod(CURVE_ORDER);
      }
    }

    return result;
  }

  clear() {
    for (let i = 0; i < this.coefficients.length; i++) {
      this.coefficients[i] = new BN(0);
    }
    this.coefficients = [];
    this.degree = 0;
  }
}

export { Polynomial, PolynomialError, generateSecureRandom, CURVE_ORDER };
export default Polynomial;
