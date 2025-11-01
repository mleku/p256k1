package p256k1

import (
	"crypto/rand"
	"testing"
)

func TestEcmultGen(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Test multiplication by zero
	var zero Scalar
	zero.setInt(0)
	var result GroupElementJacobian
	ecmultGen(&ctx.ecmultGenCtx, &result, &zero)

	if !result.isInfinity() {
		t.Error("0 * G should be infinity")
	}

	// Test multiplication by one
	var one Scalar
	one.setInt(1)
	ecmultGen(&ctx.ecmultGenCtx, &result, &one)

	if result.isInfinity() {
		t.Error("1 * G should not be infinity")
	}

	// Convert to affine and compare with generator
	var resultAffine GroupElementAffine
	resultAffine.setGEJ(&result)

	if !resultAffine.equal(&GeneratorAffine) {
		t.Error("1 * G should equal the generator point")
	}

	// Test multiplication by two
	var two Scalar
	two.setInt(2)
	ecmultGen(&ctx.ecmultGenCtx, &result, &two)

	// Should equal G + G
	var doubled GroupElementJacobian
	var genJ GroupElementJacobian
	genJ.setGE(&GeneratorAffine)
	doubled.double(&genJ)

	var resultAffine2, doubledAffine GroupElementAffine
	resultAffine2.setGEJ(&result)
	doubledAffine.setGEJ(&doubled)

	if !resultAffine2.equal(&doubledAffine) {
		t.Error("2 * G should equal G + G")
	}
}

func TestEcmultGenRandomScalars(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Test with random scalars
	for i := 0; i < 20; i++ {
		var bytes [32]byte
		rand.Read(bytes[:])
		bytes[0] &= 0x7F // Ensure no overflow

		var scalar Scalar
		scalar.setB32(bytes[:])

		if scalar.isZero() {
			continue // Skip zero
		}

		var result GroupElementJacobian
		ecmultGen(&ctx.ecmultGenCtx, &result, &scalar)

		if result.isInfinity() {
			t.Errorf("Random scalar %d should not produce infinity", i)
		}

		// Test that different scalars produce different results
		var scalar2 Scalar
		scalar2.setInt(1)
		scalar2.add(&scalar, &scalar2) // scalar + 1

		var result2 GroupElementJacobian
		ecmultGen(&ctx.ecmultGenCtx, &result2, &scalar2)

		var resultAffine, result2Affine GroupElementAffine
		resultAffine.setGEJ(&result)
		result2Affine.setGEJ(&result2)

		if resultAffine.equal(&result2Affine) {
			t.Errorf("Different scalars should produce different points (test %d)", i)
		}
	}
}

func TestEcmultConst(t *testing.T) {
	// Test constant-time scalar multiplication
	var point GroupElementAffine
	point = GeneratorAffine

	// Test multiplication by zero
	var zero Scalar
	zero.setInt(0)
	var result GroupElementJacobian
	EcmultConst(&result, &zero, &point)

	if !result.isInfinity() {
		t.Error("0 * P should be infinity")
	}

	// Test multiplication by one
	var one Scalar
	one.setInt(1)
	EcmultConst(&result, &one, &point)

	var resultAffine GroupElementAffine
	resultAffine.setGEJ(&result)

	if !resultAffine.equal(&point) {
		t.Error("1 * P should equal P")
	}

	// Test multiplication by two
	var two Scalar
	two.setInt(2)
	EcmultConst(&result, &two, &point)

	// Should equal P + P
	var pointJ GroupElementJacobian
	pointJ.setGE(&point)
	var doubled GroupElementJacobian
	doubled.double(&pointJ)

	var doubledAffine GroupElementAffine
	resultAffine.setGEJ(&result)
	doubledAffine.setGEJ(&doubled)

	if !resultAffine.equal(&doubledAffine) {
		t.Error("2 * P should equal P + P")
	}
}

func TestEcmultConstVsGen(t *testing.T) {
	// Test that EcmultConst with generator gives same result as EcmultGen
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	for i := 1; i <= 10; i++ {
		var scalar Scalar
		scalar.setInt(uint(i))

		// Use EcmultGen
		var resultGen GroupElementJacobian
		ecmultGen(&ctx.ecmultGenCtx, &resultGen, &scalar)

		// Use EcmultConst with generator
		var resultConst GroupElementJacobian
		EcmultConst(&resultConst, &scalar, &GeneratorAffine)

		// Convert to affine for comparison
		var genAffine, constAffine GroupElementAffine
		genAffine.setGEJ(&resultGen)
		constAffine.setGEJ(&resultConst)

		if !genAffine.equal(&constAffine) {
			t.Errorf("EcmultGen and EcmultConst should give same result for scalar %d", i)
		}
	}
}

func TestEcmultMulti(t *testing.T) {
	// Test multi-scalar multiplication
	var points [3]*GroupElementAffine
	var scalars [3]*Scalar

	// Initialize test data
	for i := 0; i < 3; i++ {
		points[i] = &GroupElementAffine{}
		*points[i] = GeneratorAffine

		scalars[i] = &Scalar{}
		scalars[i].setInt(uint(i + 1))
	}

	var result GroupElementJacobian
	EcmultMulti(&result, scalars[:], points[:])

	if result.isInfinity() {
		t.Error("Multi-scalar multiplication should not result in infinity for non-zero inputs")
	}

	// Verify result equals sum of individual multiplications
	var expected GroupElementJacobian
	expected.setInfinity()

	for i := 0; i < 3; i++ {
		var individual GroupElementJacobian
		EcmultConst(&individual, scalars[i], points[i])
		expected.addVar(&expected, &individual)
	}

	var resultAffine, expectedAffine GroupElementAffine
	resultAffine.setGEJ(&result)
	expectedAffine.setGEJ(&expected)

	if !resultAffine.equal(&expectedAffine) {
		t.Error("Multi-scalar multiplication should equal sum of individual multiplications")
	}
}

func TestEcmultMultiEdgeCases(t *testing.T) {
	// Test with empty arrays
	var result GroupElementJacobian
	EcmultMulti(&result, nil, nil)

	if !result.isInfinity() {
		t.Error("Multi-scalar multiplication with empty arrays should be infinity")
	}

	// Test with single element
	var points [1]*GroupElementAffine
	var scalars [1]*Scalar

	points[0] = &GeneratorAffine
	scalars[0] = &Scalar{}
	scalars[0].setInt(5)

	EcmultMulti(&result, scalars[:], points[:])

	// Should equal 5 * G
	var expected GroupElementJacobian
	EcmultConst(&expected, scalars[0], points[0])

	var resultAffine, expectedAffine GroupElementAffine
	resultAffine.setGEJ(&result)
	expectedAffine.setGEJ(&expected)

	if !resultAffine.equal(&expectedAffine) {
		t.Error("Single-element multi-scalar multiplication should equal individual multiplication")
	}
}

func TestEcmultMultiWithZeros(t *testing.T) {
	// Test multi-scalar multiplication with some zero scalars
	var points [3]*GroupElementAffine
	var scalars [3]*Scalar

	for i := 0; i < 3; i++ {
		points[i] = &GroupElementAffine{}
		*points[i] = GeneratorAffine

		scalars[i] = &Scalar{}
		if i == 1 {
			scalars[i].setInt(0) // Middle scalar is zero
		} else {
			scalars[i].setInt(uint(i + 1))
		}
	}

	var result GroupElementJacobian
	EcmultMulti(&result, scalars[:], points[:])

	// Should equal 1*G + 0*G + 3*G = 1*G + 3*G = 4*G
	var expected GroupElementJacobian
	var four Scalar
	four.setInt(4)
	EcmultConst(&expected, &four, &GeneratorAffine)

	var resultAffine, expectedAffine GroupElementAffine
	resultAffine.setGEJ(&result)
	expectedAffine.setGEJ(&expected)

	if !resultAffine.equal(&expectedAffine) {
		t.Error("Multi-scalar multiplication with zeros should skip zero terms")
	}
}

func TestEcmultProperties(t *testing.T) {
	// Test linearity: k1*P + k2*P = (k1 + k2)*P
	var k1, k2, sum Scalar
	k1.setInt(7)
	k2.setInt(11)
	sum.add(&k1, &k2)

	var result1, result2, resultSum GroupElementJacobian
	EcmultConst(&result1, &k1, &GeneratorAffine)
	EcmultConst(&result2, &k2, &GeneratorAffine)
	EcmultConst(&resultSum, &sum, &GeneratorAffine)

	// result1 + result2 should equal resultSum
	var combined GroupElementJacobian
	combined.addVar(&result1, &result2)

	var combinedAffine, sumAffine GroupElementAffine
	combinedAffine.setGEJ(&combined)
	sumAffine.setGEJ(&resultSum)

	if !combinedAffine.equal(&sumAffine) {
		t.Error("Linearity property should hold: k1*P + k2*P = (k1 + k2)*P")
	}
}

func TestEcmultDistributivity(t *testing.T) {
	// Test distributivity: k*(P + Q) = k*P + k*Q
	var k Scalar
	k.setInt(5)

	// Create two different points
	var p, q GroupElementAffine
	p = GeneratorAffine

	var two Scalar
	two.setInt(2)
	var qJ GroupElementJacobian
	EcmultConst(&qJ, &two, &p) // Q = 2*P
	q.setGEJ(&qJ)

	// Compute P + Q
	var pJ GroupElementJacobian
	pJ.setGE(&p)
	var pPlusQJ GroupElementJacobian
	pPlusQJ.addGE(&pJ, &q)
	var pPlusQ GroupElementAffine
	pPlusQ.setGEJ(&pPlusQJ)

	// Compute k*(P + Q)
	var leftSide GroupElementJacobian
	EcmultConst(&leftSide, &k, &pPlusQ)

	// Compute k*P + k*Q
	var kP, kQ GroupElementJacobian
	EcmultConst(&kP, &k, &p)
	EcmultConst(&kQ, &k, &q)
	var rightSide GroupElementJacobian
	rightSide.addVar(&kP, &kQ)

	var leftAffine, rightAffine GroupElementAffine
	leftAffine.setGEJ(&leftSide)
	rightAffine.setGEJ(&rightSide)

	if !leftAffine.equal(&rightAffine) {
		t.Error("Distributivity should hold: k*(P + Q) = k*P + k*Q")
	}
}

func TestEcmultLargeScalars(t *testing.T) {
	// Test with large scalars (close to group order)
	var largeScalar Scalar
	largeBytes := [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
	} // n - 1
	largeScalar.setB32(largeBytes[:])

	var result GroupElementJacobian
	EcmultConst(&result, &largeScalar, &GeneratorAffine)

	if result.isInfinity() {
		t.Error("(n-1) * G should not be infinity")
	}

	// (n-1) * G + G should equal infinity (since n * G = infinity)
	var genJ GroupElementJacobian
	genJ.setGE(&GeneratorAffine)
	result.addVar(&result, &genJ)

	if !result.isInfinity() {
		t.Error("(n-1) * G + G should equal infinity")
	}
}

func TestEcmultNegativeScalars(t *testing.T) {
	// Test with negative scalars (using negation)
	var k Scalar
	k.setInt(7)

	var negK Scalar
	negK.negate(&k)

	var result, negResult GroupElementJacobian
	EcmultConst(&result, &k, &GeneratorAffine)
	EcmultConst(&negResult, &negK, &GeneratorAffine)

	// negResult should be the negation of result
	var negResultNegated GroupElementJacobian
	negResultNegated.negate(&negResult)

	var resultAffine, negatedAffine GroupElementAffine
	resultAffine.setGEJ(&result)
	negatedAffine.setGEJ(&negResultNegated)

	if !resultAffine.equal(&negatedAffine) {
		t.Error("(-k) * P should equal -(k * P)")
	}
}

// Benchmark tests
func BenchmarkEcmultGen(b *testing.B) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		b.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	var scalar Scalar
	scalar.setInt(12345)
	var result GroupElementJacobian

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ecmultGen(&ctx.ecmultGenCtx, &result, &scalar)
	}
}

func BenchmarkEcmultConst(b *testing.B) {
	var point GroupElementAffine
	point = GeneratorAffine

	var scalar Scalar
	scalar.setInt(12345)
	var result GroupElementJacobian

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EcmultConst(&result, &scalar, &point)
	}
}

func BenchmarkEcmultMulti3Points(b *testing.B) {
	var points [3]*GroupElementAffine
	var scalars [3]*Scalar

	for i := 0; i < 3; i++ {
		points[i] = &GroupElementAffine{}
		*points[i] = GeneratorAffine

		scalars[i] = &Scalar{}
		scalars[i].setInt(uint(i + 1000))
	}

	var result GroupElementJacobian

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EcmultMulti(&result, scalars[:], points[:])
	}
}

func BenchmarkEcmultMulti10Points(b *testing.B) {
	var points [10]*GroupElementAffine
	var scalars [10]*Scalar

	for i := 0; i < 10; i++ {
		points[i] = &GroupElementAffine{}
		*points[i] = GeneratorAffine

		scalars[i] = &Scalar{}
		scalars[i].setInt(uint(i + 1000))
	}

	var result GroupElementJacobian

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EcmultMulti(&result, scalars[:], points[:])
	}
}
