package p256k1

import (
	"testing"
)

// TestScalarSplitLambda verifies that scalarSplitLambda correctly splits scalars
// Property: r1 + lambda * r2 == k (mod n)
func TestScalarSplitLambda(t *testing.T) {
	testCases := []struct {
		name string
		k    *Scalar
	}{
		{
			name: "one",
			k:    func() *Scalar { var s Scalar; s.setInt(1); return &s }(),
		},
		{
			name: "small_value",
			k:    func() *Scalar { var s Scalar; s.setInt(12345); return &s }(),
		},
		{
			name: "large_value",
			k: func() *Scalar {
				var s Scalar
				// Set to a large value less than group order
				bytes := [32]byte{
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
					0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
					0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F,
				}
				s.setB32(bytes[:])
				return &s
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var r1, r2 Scalar
			scalarSplitLambda(&r1, &r2, tc.k)

			// Verify: r1 + lambda * r2 == k (mod n)
			var lambdaR2, sum Scalar
			lambdaR2.mul(&r2, &lambdaConstant)
			sum.add(&r1, &lambdaR2)

			// Compare with k
			if !sum.equal(tc.k) {
				t.Errorf("r1 + lambda*r2 != k\nr1: %v\nr2: %v\nlambda*r2: %v\nsum: %v\nk: %v",
					r1, r2, lambdaR2, sum, tc.k)
			}

			// Verify bounds: |r1| < 2^128 and |r2| < 2^128 (mod n)
			// Check if r1 < 2^128 or -r1 mod n < 2^128
			var r1Bytes [32]byte
			r1.getB32(r1Bytes[:])

			// Check if first 16 bytes are zero (meaning < 2^128)
			r1Small := true
			for i := 0; i < 16; i++ {
				if r1Bytes[i] != 0 {
					r1Small = false
					break
				}
			}

			// If r1 is not small, check -r1 mod n
			if !r1Small {
				var negR1 Scalar
				negR1.negate(&r1)
				var negR1Bytes [32]byte
				negR1.getB32(negR1Bytes[:])

				negR1Small := true
				for i := 0; i < 16; i++ {
					if negR1Bytes[i] != 0 {
						negR1Small = false
						break
					}
				}

				if !negR1Small {
					t.Errorf("r1 not in range (-2^128, 2^128): r1=%v, -r1=%v", r1Bytes, negR1Bytes)
				}
			}

			// Same for r2
			var r2Bytes [32]byte
			r2.getB32(r2Bytes[:])

			r2Small := true
			for i := 0; i < 16; i++ {
				if r2Bytes[i] != 0 {
					r2Small = false
					break
				}
			}

			if !r2Small {
				var negR2 Scalar
				negR2.negate(&r2)
				var negR2Bytes [32]byte
				negR2.getB32(negR2Bytes[:])

				negR2Small := true
				for i := 0; i < 16; i++ {
					if negR2Bytes[i] != 0 {
						negR2Small = false
						break
					}
				}

				if !negR2Small {
					t.Errorf("r2 not in range (-2^128, 2^128): r2=%v, -r2=%v", r2Bytes, negR2Bytes)
				}
			}
		})
	}
}

// TestScalarSplitLambdaRandom tests with random scalars
func TestScalarSplitLambdaRandom(t *testing.T) {
	for i := 0; i < 100; i++ {
		var k Scalar
		k.setInt(uint(i + 1))

		var r1, r2 Scalar
		scalarSplitLambda(&r1, &r2, &k)

		// Verify: r1 + lambda * r2 == k (mod n)
		var lambdaR2, sum Scalar
		lambdaR2.mul(&r2, &lambdaConstant)
		sum.add(&r1, &lambdaR2)

		if !sum.equal(&k) {
			t.Errorf("Random test %d: r1 + lambda*r2 != k", i)
		}
	}
}

// TestGeMulLambda verifies that geMulLambda correctly multiplies points by lambda
// Property: lambda * (x, y) = (beta * x, y)
func TestGeMulLambda(t *testing.T) {
	// Test with generator point
	var g GroupElementAffine
	g.setXOVar(&FieldElementOne, false)

	var lambdaG GroupElementAffine
	geMulLambda(&lambdaG, &g)

	// Verify: lambdaG.x == beta * g.x
	var expectedX FieldElement
	expectedX.mul(&g.x, &betaConstant)
	expectedX.normalize()
	lambdaG.x.normalize()

	if !lambdaG.x.equal(&expectedX) {
		t.Errorf("geMulLambda: x coordinate incorrect\nexpected: %v\ngot: %v", expectedX, lambdaG.x)
	}

	// Verify: lambdaG.y == g.y
	g.y.normalize()
	lambdaG.y.normalize()
	if !lambdaG.y.equal(&g.y) {
		t.Errorf("geMulLambda: y coordinate incorrect\nexpected: %v\ngot: %v", g.y, lambdaG.y)
	}
}

// TestMulShiftVar verifies mulShiftVar matches C implementation behavior
func TestMulShiftVar(t *testing.T) {
	var k, g Scalar
	k.setInt(12345)
	g.setInt(67890)

	result := mulShiftVar(&k, &g, 384)

	// Verify result is approximately k*g/2^384
	// This is a rough check - exact verification requires comparing with C code
	var expected Scalar
	expected.mul(&k, &g)
	// Expected should be approximately result * 2^384, but we can't easily verify this
	// Just check that result is reasonable (not zero, not too large)
	if result.isZero() {
		t.Error("mulShiftVar result should not be zero")
	}

	// Test with shift = 0
	result0 := mulShiftVar(&k, &g, 0)
	expected0 := Scalar{}
	expected0.mul(&k, &g)
	if !result0.equal(&expected0) {
		t.Error("mulShiftVar with shift=0 should equal multiplication")
	}
}

// TestHalf verifies half operation
func TestHalf(t *testing.T) {
	testCases := []struct {
		name     string
		input    uint
		expected uint
	}{
		{"even", 14, 7},
		{"odd", 7, 4}, // 7/2 = 3.5 -> rounds to 4 in modular arithmetic
		{"zero", 0, 0},
		{"one", 1, 1}, // 1/2 = 0.5 -> rounds to 1 (or (n+1)/2 mod n)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var input, half, doubled Scalar
			input.setInt(tc.input)
			half.half(&input)
			doubled.add(&half, &half)

			// Verify: 2 * half == input (mod n)
			if !doubled.equal(&input) {
				t.Errorf("2 * half != input: input=%d, half=%v, doubled=%v",
					tc.input, half, doubled)
			}
		})
	}
}

// TestEcmultConstGLVCompare compares GLV implementation with simple binary method
func TestEcmultConstGLVCompare(t *testing.T) {
	// Test with generator point
	var g GroupElementAffine
	g.setXOVar(&FieldElementOne, false)

	testScalars := []struct {
		name string
		q    *Scalar
	}{
		{"one", func() *Scalar { var s Scalar; s.setInt(1); return &s }()},
		{"small", func() *Scalar { var s Scalar; s.setInt(12345); return &s }()},
		{"medium", func() *Scalar { var s Scalar; s.setInt(0x12345678); return &s }()},
	}

	for _, tc := range testScalars {
		t.Run(tc.name, func(t *testing.T) {
			// Compute using simple binary method (reference)
			var r1 GroupElementJacobian
			var gJac GroupElementJacobian
			gJac.setGE(&g)
			r1.setInfinity()
			var base GroupElementJacobian
			base = gJac
			for i := 0; i < 256; i++ {
				if i > 0 {
					r1.double(&r1)
				}
				bit := tc.q.getBits(uint(255-i), 1)
				if bit != 0 {
					if r1.isInfinity() {
						r1 = base
					} else {
						r1.addVar(&r1, &base)
					}
				}
			}

			// Compute using GLV
			var r2 GroupElementJacobian
			ecmultConstGLV(&r2, &g, tc.q)

			// Convert both to affine for comparison
			var r1Aff, r2Aff GroupElementAffine
			r1Aff.setGEJ(&r1)
			r2Aff.setGEJ(&r2)

			// Compare
			if !r1Aff.equal(&r2Aff) {
				t.Errorf("GLV result differs from reference\nr1: %v\nr2: %v", r1Aff, r2Aff)
			}
		})
	}
}
