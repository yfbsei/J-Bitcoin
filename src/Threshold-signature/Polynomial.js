import { randomBytes } from 'node:crypto';
import BN from 'bn.js';

const N = new BN("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", "hex");

class Polynomial {
    
    constructor(coefficients) {
        this.order = coefficients.length - 1;
        this.coefficients = coefficients;
    }
    
    static fromRandom(order = 2) {
        const coefficients = new Array(order+1).fill(null).map(_ => new BN(randomBytes(32)) );
        return new Polynomial(coefficients);
    }

    static interpolate_evaluate(points = [[1, 2], [1,2]], x = 2) {
        let lagrange = new Array(points.length).fill(null);
        let denominator_product = 1;

        for (let i = 0; i < points.length; i++) {
            let [numerator, denominator] = [1, 1];
            for (let j = 0; j < points.length; j++) {
                if(j !== i) {
                    numerator *= (x - points[j][0]);
                    denominator *= (points[i][0] - points[j][0]);
                }
            }
            lagrange[i] = [new BN(points[i][1]).muln(numerator), denominator];
            denominator_product *= denominator;
        }
        const numerator_sum = lagrange.reduce((total, val) => total.add( val[0].muln(denominator_product).divRound( new BN(val[1]) ) ), new BN(0));

        return numerator_sum.divRound(new BN(denominator_product)).umod(N);
    }

    evaluate(x = 2) {
        return this.coefficients.reduce((total, val) => {
            total[1].iadd(val.muln(total[0])); // y = y+(c*x)
            total[0] *= x;
            return [total[0], total[1]];
        }, [1, new BN(0)])[1].umod(N);
    }

    add(other = {order: 1, coefficients: [1, 2, 3]}) {
        
        const 
        // Differentiate
        longest = (this.order > other.order) ? this.coefficients : other.coefficients,
        shortest = (other.order < this.order) ? other.coefficients : this.coefficients,
        
        coefficients = 
        new Array(shortest.length)
        .fill(null)
        .map((_, i) => shortest[i].add(longest[i]))
        .concat(longest.slice(shortest.length)) // Concat remaining unique values
        .map(val => val.umod(N));

        return new Polynomial(coefficients);
    }

    multiply(other = {order: 1, coefficients: [1, 2, 3]}) {
        let coefficients = new Array(this.order + other.order + 1).fill(new BN(0));

        for (let i = 0; i < this.coefficients.length; i++) {
            for (let j = 0; j < other.coefficients.length; j++) {
                coefficients[i+j] = coefficients[i+j].add( this.coefficients[i].mul(other.coefficients[j]) );
            }
        }
        
        coefficients = coefficients.map(val => val.umod(N));
        return new Polynomial(coefficients);
    }
}

export default Polynomial;
