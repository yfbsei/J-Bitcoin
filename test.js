/**
 * @fileoverview Comprehensive test suite for polynomial.js
 * Tests import functionality, basic operations, and advanced features
 * Run with: node test.js
 */

import Polynomial, {
    PolynomialError,
    PolynomialSecurityUtils,
    PolynomialUtils,
    POLYNOMIAL_SECURITY_CONSTANTS
} from './src/core/crypto/signatures/threshold/polynomial.js';
import BN from 'bn.js';

/**
 * Test runner with colored output
 */
class TestRunner {
    constructor() {
        this.passed = 0;
        this.failed = 0;
        this.errors = [];
    }

    async runTest(name, testFunction) {
        try {
            console.log(`🧪 Testing: ${name}`);
            await testFunction();
            console.log(`✅ PASSED: ${name}`);
            this.passed++;
        } catch (error) {
            console.error(`❌ FAILED: ${name}`);
            console.error(`   Error: ${error.message}`);
            this.failed++;
            this.errors.push({ test: name, error: error.message });
        }
    }

    printSummary() {
        console.log('\n' + '='.repeat(60));
        console.log('📊 TEST SUMMARY');
        console.log('='.repeat(60));
        console.log(`Total Tests: ${this.passed + this.failed}`);
        console.log(`✅ Passed: ${this.passed}`);
        console.log(`❌ Failed: ${this.failed}`);
        console.log(`Success Rate: ${((this.passed / (this.passed + this.failed)) * 100).toFixed(1)}%`);

        if (this.failed > 0) {
            console.log('\n❌ Failed Tests:');
            this.errors.forEach(({ test, error }) => {
                console.log(`  • ${test}: ${error}`);
            });
        }

        console.log('\n🎉 Test run complete!');
    }

    assert(condition, message) {
        if (!condition) {
            throw new Error(`Assertion failed: ${message}`);
        }
    }
}

/**
 * Main test suite
 */
async function runPolynomialTests() {
    const runner = new TestRunner();

    console.log('🚀 Starting Polynomial.js Test Suite');
    console.log('====================================\n');

    // =================================================================
    // IMPORT TESTS
    // =================================================================

    await runner.runTest('Import Default Export', () => {
        runner.assert(typeof Polynomial === 'function', 'Polynomial should be a constructor function');
        runner.assert(Polynomial.name === 'Polynomial', 'Constructor should be named Polynomial');
    });

    await runner.runTest('Import Named Exports', () => {
        runner.assert(typeof PolynomialError === 'function', 'PolynomialError should be exported');
        runner.assert(typeof PolynomialSecurityUtils === 'function', 'PolynomialSecurityUtils should be exported');
        runner.assert(typeof PolynomialUtils === 'function', 'PolynomialUtils should be exported');
        runner.assert(typeof POLYNOMIAL_SECURITY_CONSTANTS === 'object', 'Constants should be exported');
    });

    // =================================================================
    // BASIC CONSTRUCTION TESTS
    // =================================================================

    await runner.runTest('Basic Polynomial Construction', () => {
        const coeffs = [new BN(5), new BN(3), new BN(1)]; // 5 + 3x + x^2
        const poly = new Polynomial(coeffs);

        runner.assert(poly instanceof Polynomial, 'Should create Polynomial instance');
        runner.assert(poly.degree === 2, 'Degree should be 2');
        runner.assert(poly.coefficients.length === 3, 'Should have 3 coefficients');
        runner.assert(poly.constantTerm.eq(new BN(5)), 'Constant term should be 5');
        runner.assert(poly.isValid === true, 'Polynomial should be valid');
    });

    await runner.runTest('Polynomial Normalization', () => {
        const coeffs = [new BN(1), new BN(2), new BN(0), new BN(0)]; // Should normalize to 1 + 2x
        const poly = new Polynomial(coeffs);

        runner.assert(poly.degree === 1, 'Should normalize degree to 1');
        runner.assert(poly.coefficients.length === 2, 'Should have 2 coefficients after normalization');
    });

    await runner.runTest('Invalid Construction - Empty Array', () => {
        try {
            new Polynomial([]);
            runner.assert(false, 'Should throw error for empty coefficients');
        } catch (error) {
            runner.assert(error instanceof PolynomialError, 'Should throw PolynomialError');
        }
    });

    await runner.runTest('Invalid Construction - Non-BN Coefficients', () => {
        try {
            new Polynomial([new BN(1), "invalid", new BN(3)]);
            runner.assert(false, 'Should throw error for invalid coefficients');
        } catch (error) {
            runner.assert(error instanceof PolynomialError, 'Should throw PolynomialError');
        }
    });

    // =================================================================
    // POLYNOMIAL EVALUATION TESTS
    // =================================================================

    await runner.runTest('Basic Polynomial Evaluation', () => {
        const coeffs = [new BN(5), new BN(3), new BN(1)]; // 5 + 3x + x^2
        const poly = new Polynomial(coeffs);

        // f(0) = 5
        const result0 = poly.evaluate(new BN(0));
        runner.assert(result0.value.eq(new BN(5)), 'f(0) should equal 5');
        runner.assert(result0.isValid === true, 'Result should be valid');

        // f(1) = 5 + 3 + 1 = 9
        const result1 = poly.evaluate(new BN(1));
        runner.assert(result1.value.eq(new BN(9)), 'f(1) should equal 9');

        // f(2) = 5 + 6 + 4 = 15
        const result2 = poly.evaluate(new BN(2));
        runner.assert(result2.value.eq(new BN(15)), 'f(2) should equal 15');
    });

    await runner.runTest('Evaluation Metadata', () => {
        const poly = new Polynomial([new BN(1), new BN(2)]);
        const x = new BN(3);
        const result = poly.evaluate(x);

        runner.assert(result.point.eq(x), 'Should preserve evaluation point');
        runner.assert(result.degree === poly.degree, 'Should include polynomial degree');
        runner.assert(typeof result.executionTime === 'number', 'Should include execution time');
    });

    // =================================================================
    // RANDOM GENERATION TESTS
    // =================================================================

    await runner.runTest('Random Polynomial Generation', () => {
        const degree = 3;
        const poly = Polynomial.generateRandom(degree);

        runner.assert(poly instanceof Polynomial, 'Should create Polynomial instance');
        runner.assert(poly.degree === degree, `Degree should be ${degree}`);
        runner.assert(poly.coefficients.length === degree + 1, 'Should have correct number of coefficients');
        runner.assert(poly.isValid === true, 'Generated polynomial should be valid');
    });

    await runner.runTest('Random Generation with Secret', () => {
        const degree = 2;
        const secret = new BN(12345);
        const poly = Polynomial.generateRandom(degree, secret);

        runner.assert(poly.constantTerm.eq(secret), 'Constant term should match secret');
        runner.assert(poly.degree === degree, 'Degree should be correct');
    });

    await runner.runTest('Random Generation Uniqueness', () => {
        const poly1 = Polynomial.generateRandom(2);
        const poly2 = Polynomial.generateRandom(2);

        runner.assert(!poly1.equals(poly2), 'Random polynomials should be different');
    });

    // =================================================================
    // ARITHMETIC OPERATIONS TESTS
    // =================================================================

    await runner.runTest('Polynomial Addition', () => {
        const poly1 = new Polynomial([new BN(1), new BN(2)]); // 1 + 2x
        const poly2 = new Polynomial([new BN(3), new BN(4)]); // 3 + 4x
        const sum = poly1.add(poly2); // Should be 4 + 6x

        runner.assert(sum.coefficients[0].eq(new BN(4)), 'Constant term should be 4');
        runner.assert(sum.coefficients[1].eq(new BN(6)), 'Linear term should be 6');
    });

    await runner.runTest('Polynomial Multiplication', () => {
        const poly1 = new Polynomial([new BN(1), new BN(1)]); // 1 + x
        const poly2 = new Polynomial([new BN(1), new BN(1)]); // 1 + x
        const product = poly1.multiply(poly2); // Should be 1 + 2x + x^2

        runner.assert(product.degree === 2, 'Degree should be 2');
        runner.assert(product.coefficients[0].eq(new BN(1)), 'Constant term should be 1');
        runner.assert(product.coefficients[1].eq(new BN(2)), 'Linear term should be 2');
        runner.assert(product.coefficients[2].eq(new BN(1)), 'Quadratic term should be 1');
    });

    await runner.runTest('Polynomial Equality', () => {
        const poly1 = new Polynomial([new BN(1), new BN(2), new BN(3)]);
        const poly2 = new Polynomial([new BN(1), new BN(2), new BN(3)]);
        const poly3 = new Polynomial([new BN(1), new BN(2), new BN(4)]);

        runner.assert(poly1.equals(poly2), 'Identical polynomials should be equal');
        runner.assert(!poly1.equals(poly3), 'Different polynomials should not be equal');
    });

    await runner.runTest('Polynomial Cloning', () => {
        const original = new Polynomial([new BN(1), new BN(2), new BN(3)]);
        const clone = original.clone();

        runner.assert(original.equals(clone), 'Clone should equal original');
        runner.assert(original !== clone, 'Clone should be different object');

        // Modify clone to ensure independence
        clone.coefficients[0] = new BN(999);
        runner.assert(!original.coefficients[0].eq(new BN(999)), 'Original should be unchanged');
    });

    // =================================================================
    // LAGRANGE INTERPOLATION TESTS
    // =================================================================

    await runner.runTest('Lagrange Interpolation at Zero', () => {
        // Create known polynomial: f(x) = 5 + 3x + x^2
        const originalPoly = new Polynomial([new BN(5), new BN(3), new BN(1)]);

        // Generate points from the polynomial
        const points = [
            [new BN(1), originalPoly.evaluate(new BN(1)).value],
            [new BN(2), originalPoly.evaluate(new BN(2)).value],
            [new BN(3), originalPoly.evaluate(new BN(3)).value]
        ];

        // Interpolate back to get constant term
        const result = Polynomial.interpolateAtZero(points);

        runner.assert(result.isValid === true, 'Interpolation should be valid');
        runner.assert(result.value.eq(new BN(5)), 'Should recover constant term (5)');
        runner.assert(result.pointsUsed === 3, 'Should use all 3 points');
    });

    await runner.runTest('Interpolation at Arbitrary Point', () => {
        const originalPoly = new Polynomial([new BN(1), new BN(2), new BN(3)]); // 1 + 2x + 3x^2
        const targetPoint = new BN(5);
        const expectedValue = originalPoly.evaluate(targetPoint).value;

        const points = [
            [new BN(1), originalPoly.evaluate(new BN(1)).value],
            [new BN(2), originalPoly.evaluate(new BN(2)).value],
            [new BN(3), originalPoly.evaluate(new BN(3)).value]
        ];

        const result = Polynomial.interpolateAt(points, targetPoint);
        runner.assert(result.value.eq(expectedValue), 'Should interpolate correctly at arbitrary point');
    });

    await runner.runTest('Interpolation Validation', () => {
        const originalPoly = new Polynomial([new BN(123), new BN(456)]);
        const points = [
            [new BN(1), originalPoly.evaluate(new BN(1)).value],
            [new BN(2), originalPoly.evaluate(new BN(2)).value]
        ];

        const result = Polynomial.interpolateAtZero(points);
        const validation = Polynomial.validateInterpolation(points, result.value, originalPoly);

        runner.assert(validation.isValid === true, 'Validation should pass');
        runner.assert(validation.issues.length === 0, 'Should have no validation issues');
    });

    // =================================================================
    // SECRET SHARING TESTS
    // =================================================================

    await runner.runTest('Secret Sharing - Generate and Reconstruct', () => {
        const secret = new BN(42);
        const threshold = 3;
        const numShares = 5;

        // Create polynomial with secret as constant term
        const poly = Polynomial.generateRandom(threshold - 1, secret);

        // Generate shares
        const shares = PolynomialUtils.generateShares(poly, numShares);
        runner.assert(shares.length === numShares, `Should generate ${numShares} shares`);

        // Reconstruct secret using minimum threshold
        const reconstructionShares = shares.slice(0, threshold);
        const reconstructedSecret = PolynomialUtils.reconstructSecret(reconstructionShares);

        runner.assert(reconstructedSecret.eq(secret), 'Should reconstruct original secret');
    });

    await runner.runTest('Secret Sharing - Insufficient Shares', () => {
        const secret = new BN(123);
        const threshold = 3;
        const poly = Polynomial.generateRandom(threshold - 1, secret);
        const shares = PolynomialUtils.generateShares(poly, 5);

        // Try to reconstruct with fewer than threshold shares
        const insufficientShares = shares.slice(0, threshold - 1);
        const reconstructed = PolynomialUtils.reconstructSecret(insufficientShares);

        // Should NOT equal the original secret (with high probability)
        runner.assert(!reconstructed.eq(secret), 'Should not reconstruct secret with insufficient shares');
    });

    // =================================================================
    // UTILITY AND HELPER TESTS
    // =================================================================

    await runner.runTest('Polynomial String Representation', () => {
        const poly = new Polynomial([new BN(5), new BN(3), new BN(1)]); // 5 + 3x + x^2
        const str = poly.toString();

        runner.assert(typeof str === 'string', 'Should return string');
        runner.assert(str.includes('5'), 'Should include constant term');
        runner.assert(str.includes('x'), 'Should include variable terms');
    });

    await runner.runTest('Polynomial Metadata', () => {
        const poly = new Polynomial([new BN(1), new BN(2), new BN(3)]);
        const metadata = poly.getMetadata();

        runner.assert(typeof metadata === 'object', 'Should return metadata object');
        runner.assert(metadata.degree === 2, 'Should include degree');
        runner.assert(metadata.coefficientCount === 3, 'Should include coefficient count');
        runner.assert(metadata.isValid === true, 'Should include validity status');
    });

    await runner.runTest('Polynomial Validation', () => {
        const poly = new Polynomial([new BN(1), new BN(2)]);
        const validation = poly.validate();

        runner.assert(validation.isValid === true, 'Valid polynomial should pass validation');
        runner.assert(Array.isArray(validation.issues), 'Should include issues array');
        runner.assert(validation.issues.length === 0, 'Valid polynomial should have no issues');
    });

    await runner.runTest('Export and Import Data', () => {
        const original = new Polynomial([new BN(123), new BN(456), new BN(789)]);
        const exported = original.exportData();

        runner.assert(typeof exported === 'object', 'Should export to object');
        runner.assert(exported.degree === original.degree, 'Should preserve degree');

        const imported = Polynomial.importData(exported);
        runner.assert(original.equals(imported), 'Should import correctly');
    });

    // =================================================================
    // ERROR HANDLING TESTS
    // =================================================================

    await runner.runTest('Error Handling - Invalid Evaluation Point', () => {
        const poly = new Polynomial([new BN(1), new BN(2)]);

        try {
            poly.evaluate("invalid");
            runner.assert(false, 'Should throw error for invalid evaluation point');
        } catch (error) {
            runner.assert(error instanceof PolynomialError, 'Should throw PolynomialError');
        }
    });

    await runner.runTest('Error Handling - Duplicate X Coordinates', () => {
        const points = [
            [new BN(1), new BN(100)],
            [new BN(1), new BN(200)], // Duplicate x-coordinate
            [new BN(2), new BN(300)]
        ];

        try {
            Polynomial.interpolateAtZero(points);
            runner.assert(false, 'Should throw error for duplicate x-coordinates');
        } catch (error) {
            runner.assert(error instanceof PolynomialError, 'Should throw PolynomialError');
            runner.assert(error.code === 'DUPLICATE_X_COORDINATE', 'Should have correct error code');
        }
    });

    // =================================================================
    // SECURITY AND PERFORMANCE TESTS
    // =================================================================

    await runner.runTest('Security Constants', () => {
        runner.assert(typeof POLYNOMIAL_SECURITY_CONSTANTS.MAX_DEGREE === 'number', 'Should define max degree');
        runner.assert(typeof POLYNOMIAL_SECURITY_CONSTANTS.MAX_COEFFICIENTS === 'number', 'Should define max coefficients');
        runner.assert(typeof POLYNOMIAL_SECURITY_CONSTANTS.MAX_VALIDATIONS_PER_SECOND === 'number', 'Should define rate limits');
    });

    await runner.runTest('Implementation Status', () => {
        const status = Polynomial.getStatus();

        runner.assert(typeof status === 'object', 'Should return status object');
        runner.assert(typeof status.version === 'string', 'Should include version');
        runner.assert(Array.isArray(status.enhancements), 'Should include enhancements list');
        runner.assert(typeof status.constants === 'object', 'Should include constants');
    });

    await runner.runTest('Built-in Test Suite', () => {
        const testResults = Polynomial.runTests();

        runner.assert(typeof testResults === 'object', 'Should return test results');
        runner.assert(typeof testResults.passed === 'number', 'Should include passed count');
        runner.assert(typeof testResults.failed === 'number', 'Should include failed count');
        runner.assert(testResults.passed > 0, 'Should have some passing tests');
    });

    await runner.runTest('Secure Cleanup', () => {
        const poly = new Polynomial([new BN(12345), new BN(67890)]);
        const originalValid = poly.isValid;

        poly.destroy();

        runner.assert(originalValid === true, 'Polynomial should have been valid initially');
        runner.assert(poly.isValid === false, 'Polynomial should be invalid after destruction');
        runner.assert(poly.coefficients.length === 0, 'Coefficients should be cleared');
    });

    // =================================================================
    // EDGE CASES AND STRESS TESTS
    // =================================================================

    await runner.runTest('Edge Case - Single Coefficient Polynomial', () => {
        const poly = new Polynomial([new BN(42)]);

        runner.assert(poly.degree === 0, 'Should have degree 0');
        runner.assert(poly.evaluate(new BN(999)).value.eq(new BN(42)), 'Should always evaluate to constant');
    });

    await runner.runTest('Edge Case - Large Numbers', () => {
        // Use large but valid field elements
        const largeBN = new BN('123456789012345678901234567890');
        const poly = new Polynomial([largeBN]);

        runner.assert(poly.isValid === true, 'Should handle large numbers');
        runner.assert(poly.constantTerm.gt(new BN(0)), 'Should preserve large values');
    });

    await runner.runTest('Performance - Multiple Operations', () => {
        const startTime = Date.now();

        // Perform multiple operations to test performance
        for (let i = 0; i < 10; i++) {
            const poly = Polynomial.generateRandom(3);
            const result = poly.evaluate(new BN(i + 1));
            runner.assert(result.isValid === true, `Operation ${i} should be valid`);
        }

        const elapsed = Date.now() - startTime;
        runner.assert(elapsed < 5000, 'Multiple operations should complete within 5 seconds');
    });

    // Print final summary
    runner.printSummary();

    // Exit with appropriate code
    process.exit(runner.failed === 0 ? 0 : 1);
}

/**
 * Error handling for the test suite
 */
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

// Run the test suite
console.log('🔍 Checking imports...');
try {
    console.log('✅ All imports successful');
    console.log('- Polynomial:', typeof Polynomial);
    console.log('- PolynomialError:', typeof PolynomialError);
    console.log('- PolynomialUtils:', typeof PolynomialUtils);
    console.log('- Constants:', typeof POLYNOMIAL_SECURITY_CONSTANTS);
    console.log('');

    // Start the main test suite
    runPolynomialTests();

} catch (error) {
    console.error('❌ Import failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}