import Polynomial from "./Polynomial.js";
import { secp256k1 } from '@noble/curves/secp256k1';
import BN from "bn.js";
import { createHash } from 'node:crypto';
import { bufToBigint } from 'bigint-conversion';

// secp256k1 curve order for modular arithmetic
const N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", "hex");

class ThresholdSignature {
	constructor(group_size = 3, threshold = 2) {
		this.group_size = group_size;
		this.polynomial_order = threshold - 1;
		this.threshold = threshold;

		if (this.polynomial_order < 1 || this.threshold > this.group_size) {
			throw new Error("Threshold is too high or low")
		}

		[this.shares, this.public_key] = this.jvrss();
	}

	shares_to_points(shares = []) {
		return shares.map((x, i) => [i + 1, x]);
	}

	jvrss() {
		const polynomials = new Array(this.group_size)
			.fill(null)
			.map(_ => Polynomial.fromRandom(this.polynomial_order));

		let shares = new Array(this.group_size).fill(new BN(0));

		for (let i = 0; i < this.group_size; i++) {
			for (let j = 0; j < this.group_size; j++) {
				shares[j] = shares[j].add(polynomials[i].evaluate(j + 1));
			}
		}

		shares = shares.map(val => val.umod(N));

		let public_key = secp256k1.ProjectivePoint.ZERO;
		for (let i = 0; i < this.group_size; i++) {
			const key = polynomials[i].coefficients[0].toBuffer("be", 32);
			public_key = secp256k1.ProjectivePoint.fromPrivateKey(key).add(public_key);
		}

		return [shares, public_key];
	}

	addss(a_shares = [], b_shares = []) {
		const shares_addition = new Array(this.group_size)
			.fill(null)
			.map((_, i) => a_shares[i].add(b_shares[i]).umod(N));

		const random_points = this.shares_to_points(shares_addition)
			.sort(() => 0.5 - Math.random())
			.slice(0, this.polynomial_order + 1);

		return Polynomial.interpolate_evaluate(random_points, 0);
	}

	pross(a_shares = [], b_shares = []) {
		const shares_product = new Array(this.group_size)
			.fill(null)
			.map((_, i) => a_shares[i].mul(b_shares[i]).umod(N));

		const random_points = this.shares_to_points(shares_product)
			.sort(() => 0.5 - Math.random())
			.slice(0, 2 * this.polynomial_order + 1);

		return Polynomial.interpolate_evaluate(random_points, 0);
	}

	invss(a_shares = []) {
		const [b_shares, _] = this.jvrss();
		const pross = this.pross(a_shares, b_shares);

		// FIXED: Use BN.js for modular inverse calculation
		const x_bn = new BN(pross.toBuffer('be', 32));
		const curveOrder_bn = new BN(secp256k1.CURVE.n.toString());

		// Compute modular inverse using Fermat's Little Theorem: a^(p-2) ≡ a^(-1) (mod p)
		const exponent = curveOrder_bn.sub(new BN(2));
		const mod_inv_bn = x_bn.toRed(BN.red(curveOrder_bn)).redPow(exponent).fromRed();

		const inverse_shares = b_shares.map(val => mod_inv_bn.mul(val).umod(N));
		return inverse_shares;
	}

	privite_key(a_shares) {
		a_shares = a_shares || this.shares;
		return Polynomial.interpolate_evaluate(this.shares_to_points(a_shares), 0);
	}

	sign(message) {
		const msgHash = new BN(createHash('sha256').update(Buffer.from(message)).digest());
		let [recovery_id, r, s] = [0, 0, 0];

		while (!s) {
			let invss_shares = [];

			while (!r) {
				const [k_shares, k_public_key] = this.jvrss();
				const [k_x, k_y] = [new BN(k_public_key.x), new BN(k_public_key.y)];
				r = k_x.umod(N);

				recovery_id = 0 | k_x.gt(N) ? 2 : 0 | k_y.modrn(2);
				invss_shares = this.invss(k_shares);
			}

			let s_shares = [];
			for (let i = 0; i < this.group_size; i++) {
				s_shares.push(
					r.mul(this.shares[i]).add(msgHash).mul(invss_shares[i])
				);
			}

			s = Polynomial.interpolate_evaluate(this.shares_to_points(s_shares), 0);
		}

		[r, s] = [r.toBuffer(), s.toBuffer()];
		const prefix = new BN(27 + recovery_id + 4).toBuffer();
		const serialized_sig = Buffer.concat([prefix, r, s]).toString('base64');

		return {
			sig: secp256k1.Signature.fromCompact(Buffer.concat([r, s])),
			serialized_sig,
			msgHash: msgHash.toBuffer(),
			recovery_id
		};
	}

	static verify_threshold_signature(public_key, msgHash, sig) {
		msgHash = new BN(msgHash);

		// FIXED: Use BN.js for modular inverse calculation
		const s_bn = new BN(sig.s);
		const curveOrder_bn = new BN(secp256k1.CURVE.n.toString());

		// Compute modular inverse using Fermat's Little Theorem with BN.js
		const exponent = curveOrder_bn.sub(new BN(2));
		const w = s_bn.toRed(BN.red(curveOrder_bn)).redPow(exponent).fromRed();

		const u1 = w.mul(msgHash).umod(N).toBuffer('be', 32);
		const u2 = w.mul(new BN(sig.r)).umod(N).toBuffer('be', 32);

		const x = secp256k1.ProjectivePoint.fromPrivateKey(u1)
			.add(public_key.multiply(bufToBigint(u2))).x

		return sig.r === x % secp256k1.CURVE.n;
	}
}

export default ThresholdSignature;