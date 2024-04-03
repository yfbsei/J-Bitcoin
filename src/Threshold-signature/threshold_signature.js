import Polynomial from "./Polynomial.js";
import { Point, utils, CURVE, Signature } from "@noble/secp256k1";
import BN from "bn.js";

import { createHash } from 'node:crypto';
import { bufToBigint } from 'bigint-conversion';


const N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", "hex");

class ThresholdSignature {

	constructor(group_size = 3, threshold = 2) {
		this.group_size = group_size;
		this.polynomial_order = threshold - 1;
		this.threshold = threshold;
		//this.signature_threshold = 2 * threshold; // this.signature_threshold > this.group_size
		
		if(this.polynomial_order < 1 || this.threshold > this.group_size) {
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
		let public_key = new Point(BigInt(0), BigInt(0));

		for (let i = 0; i < this.group_size; i++) {
			const key = polynomials[i].coefficients[0].toBuffer("be", 32);
			public_key = Point.fromPrivateKey(key).add(public_key); // (coefficient * g) + public key
		}

		return [shares, public_key];
	}
	

	addss(a_shares = [], b_shares = []) {
		// both groups have to be same length as group size
		const
			shares_addition = new Array(this.group_size)
			.fill(null)
			.map((_, i) => a_shares[i].add(b_shares[i]).umod(N)),

			random_points = this.shares_to_points(shares_addition)
			.sort(() => 0.5 - Math.random()) // randomize 
			.slice(0, this.polynomial_order + 1), // t + 1

			secrets_addition = Polynomial.interpolate_evaluate(random_points, 0);

			return secrets_addition;
	}

	pross(a_shares = [], b_shares = []) {
		// both groups have to be same length as group size
		const
			shares_product = new Array(this.group_size)
			.fill(null)
			.map((_, i) => a_shares[i].mul(b_shares[i]).umod(N)),

			random_points = this.shares_to_points(shares_product)
			.sort(() => 0.5 - Math.random()) // randomize 
			.slice(0, 2 * this.polynomial_order + 1), // 2t + 1

			secrets_product = Polynomial.interpolate_evaluate(random_points, 0);

		return secrets_product;
	}

	invss(a_shares = []) {
	    const 
			[b_shares, _] = this.jvrss(),
	    	pross = this.pross(a_shares, b_shares),
			x = bufToBigint(pross.toBuffer('be', 32)),
	    	mod_inv_u = new BN(utils.invert(x, CURVE.n)),
	    	inverse_shares = b_shares.map(val => mod_inv_u.mul(val).umod(N));
			
	    return inverse_shares;
	}

	privite_key(a_shares) { // Restore privite key from shares

		//points.length < this.threshold ? "The number of points is less than the threshold" : false; // Error
		a_shares = a_shares || this.shares;
		return Polynomial.interpolate_evaluate(this.shares_to_points(a_shares), 0);
	}

	// TODO - clean up //
	sign(message) {
		const msgHash = new BN( createHash('sha256').update( Buffer.from(message) ).digest() );
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
					r.mul(this.shares[i]).add(msgHash).mul(invss_shares[i]) // (sha256 + (r * t)) * c
				);
			}
			s = Polynomial.interpolate_evaluate(this.shares_to_points( s_shares ), 0); // this.signature_threshold
		}
		
		[r, s] = [r.toBuffer(), s.toBuffer()];
		const 
			prefix = new BN(27 + recovery_id + 4).toBuffer(),
			serialized_sig = Buffer.concat([prefix, r, s]).toString('base64'); // serialized compact signature

		return {
			sig: new Signature( bufToBigint(r), bufToBigint(s) ),
			serialized_sig,
			msgHash: msgHash.toBuffer(),
			recovery_id
		};
	}

	static verify_threshold_signature(public_key, msgHash, sig) {
	msgHash = new BN(msgHash);
	const
		w = new BN(utils.invert(sig.s, CURVE.n)),
		u1 = w.mul(msgHash).umod(N).toBuffer('be', 32),
		u2 = w.mul(new BN(sig.r)).umod(N).toBuffer('be', 32);

		const x = Point.fromPrivateKey(u1).add( public_key.multiply(bufToBigint(u2)) ).x

		return sig.r === x % CURVE.n;
	}
}

export default ThresholdSignature;
