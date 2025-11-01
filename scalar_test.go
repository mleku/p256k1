package p256k1

import (
	"crypto/rand"
	"testing"
)

func TestScalarBasics(t *testing.T) {
	// Test zero scalar
	var zero Scalar
	zero.setInt(0)
	if !zero.isZero() {
		t.Error("Zero scalar should be zero")
	}

	// Test one scalar
	var one Scalar
	one.setInt(1)
	if one.isZero() {
		t.Error("One scalar should not be zero")
	}
	if !one.isOne() {
		t.Error("One scalar should be one")
	}

	// Test equality
	var one2 Scalar
	one2.setInt(1)
	if !one.equal(&one2) {
		t.Error("Two ones should be equal")
	}
}

func TestScalarSetB32(t *testing.T) {
	testCases := []struct {
		name     string
		bytes    [32]byte
		overflow bool
	}{
		{
			name:     "zero",
			bytes:    [32]byte{},
			overflow: false,
		},
		{
			name:     "one",
			bytes:    [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			overflow: false,
		},
		{
			name: "group_order_minus_one",
			bytes: [32]byte{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
				0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
				0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
			},
			overflow: false,
		},
		{
			name: "group_order",
			bytes: [32]byte{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
				0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
				0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
			},
			overflow: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var s Scalar
			overflow := s.setB32(tc.bytes[:])

			if overflow != tc.overflow {
				t.Errorf("Expected overflow %v, got %v", tc.overflow, overflow)
			}

			// Test round-trip for non-overflowing values
			if !tc.overflow {
				var result [32]byte
				s.getB32(result[:])

				// Values should match after round-trip
				for i := 0; i < 32; i++ {
					if result[i] != tc.bytes[i] {
						t.Errorf("Round-trip failed at byte %d: expected %02x, got %02x", i, tc.bytes[i], result[i])
						break
					}
				}
			}
		})
	}
}

func TestScalarSetB32Seckey(t *testing.T) {
	// Test valid secret key
	validKey := [32]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	var s Scalar
	if !s.setB32Seckey(validKey[:]) {
		t.Error("Valid secret key should be accepted")
	}

	// Test zero key (invalid)
	zeroKey := [32]byte{}
	if s.setB32Seckey(zeroKey[:]) {
		t.Error("Zero secret key should be rejected")
	}

	// Test overflowing key (invalid)
	overflowKey := [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}
	if s.setB32Seckey(overflowKey[:]) {
		t.Error("Overflowing secret key should be rejected")
	}
}

func TestScalarArithmetic(t *testing.T) {
	// Test addition
	var a, b, c Scalar
	a.setInt(5)
	b.setInt(7)
	c.add(&a, &b)

	var expected Scalar
	expected.setInt(12)

	if !c.equal(&expected) {
		t.Error("5 + 7 should equal 12")
	}

	// Test multiplication
	var mult Scalar
	mult.mul(&a, &b)

	expected.setInt(35)
	if !mult.equal(&expected) {
		t.Error("5 * 7 should equal 35")
	}

	// Test negation
	var neg Scalar
	neg.negate(&a)

	var sum Scalar
	sum.add(&a, &neg)

	if !sum.isZero() {
		t.Error("a + (-a) should equal zero")
	}
}

func TestScalarInverse(t *testing.T) {
	// Test inverse of small numbers
	for i := uint(1); i <= 10; i++ {
		var a, inv, product Scalar
		a.setInt(i)
		inv.inverse(&a)
		product.mul(&a, &inv)

		if !product.isOne() {
			t.Errorf("a * a^(-1) should equal 1 for a = %d", i)
		}
	}

	// Test inverse of zero should not crash (though result is undefined)
	var zero, inv Scalar
	zero.setInt(0)
	inv.inverse(&zero) // Should not crash
}

func TestScalarHalf(t *testing.T) {
	// Test halving even numbers
	var even, half Scalar
	even.setInt(10)
	half.half(&even)

	var expected Scalar
	expected.setInt(5)

	if !half.equal(&expected) {
		t.Error("10 / 2 should equal 5")
	}

	// Test halving odd numbers
	var odd Scalar
	odd.setInt(7)
	half.half(&odd)

	// 7/2 mod n should be (7 + n)/2 mod n
	// This is more complex to verify, so we just check that 2*half = 7
	var doubled Scalar
	doubled.setInt(2)
	doubled.mul(&doubled, &half)

	if !doubled.equal(&odd) {
		t.Error("2 * (7/2) should equal 7")
	}
}

func TestScalarProperties(t *testing.T) {
	// Test even/odd detection
	var even, odd Scalar
	even.setInt(42)
	odd.setInt(43)

	if !even.isEven() {
		t.Error("42 should be even")
	}
	if odd.isEven() {
		t.Error("43 should be odd")
	}

	// Test high/low detection (compared to n/2)
	var low, high Scalar
	low.setInt(1)
	
	// Set high to a large value (close to group order)
	highBytes := [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
	}
	high.setB32(highBytes[:])

	if low.isHigh() {
		t.Error("Small value should not be high")
	}
	if !high.isHigh() {
		t.Error("Large value should be high")
	}
}

func TestScalarConditionalNegate(t *testing.T) {
	var s Scalar
	s.setInt(42)

	// Test conditional negate with false
	negated := s.condNegate(false)
	if negated {
		t.Error("Should not negate when flag is false")
	}

	var expected Scalar
	expected.setInt(42)
	if !s.equal(&expected) {
		t.Error("Value should not change when flag is false")
	}

	// Test conditional negate with true
	negated = s.condNegate(true)
	if !negated {
		t.Error("Should negate when flag is true")
	}

	var neg Scalar
	expected.setInt(42)
	neg.negate(&expected)
	if !s.equal(&neg) {
		t.Error("Value should be negated when flag is true")
	}
}

func TestScalarGetBits(t *testing.T) {
	// Test bit extraction
	var s Scalar
	s.setInt(0b11010110) // 214 in binary

	// Extract different bit ranges
	bits := s.getBits(0, 4) // Lower 4 bits: 0110 = 6
	if bits != 6 {
		t.Errorf("Expected 6, got %d", bits)
	}

	bits = s.getBits(4, 4) // Next 4 bits: 1101 = 13
	if bits != 13 {
		t.Errorf("Expected 13, got %d", bits)
	}

	bits = s.getBits(1, 3) // 3 bits starting at position 1: 011 = 3
	if bits != 3 {
		t.Errorf("Expected 3, got %d", bits)
	}
}

func TestScalarConditionalMove(t *testing.T) {
	var a, b, result Scalar
	a.setInt(10)
	b.setInt(20)
	result = a

	// Test conditional move with flag = 0 (no move)
	result.cmov(&b, 0)
	if !result.equal(&a) {
		t.Error("cmov with flag=0 should not change value")
	}

	// Test conditional move with flag = 1 (move)
	result = a
	result.cmov(&b, 1)
	if !result.equal(&b) {
		t.Error("cmov with flag=1 should change value")
	}
}

func TestScalarClear(t *testing.T) {
	var s Scalar
	s.setInt(12345)

	s.clear()

	// After clearing, should be zero
	if !s.isZero() {
		t.Error("Cleared scalar should be zero")
	}
}

func TestScalarRandomOperations(t *testing.T) {
	// Test with random values
	for i := 0; i < 50; i++ {
		var bytes1, bytes2 [32]byte
		rand.Read(bytes1[:])
		rand.Read(bytes2[:])

		var a, b Scalar
		// Ensure we don't overflow
		bytes1[0] &= 0x7F
		bytes2[0] &= 0x7F
		
		a.setB32(bytes1[:])
		b.setB32(bytes2[:])

		// Skip if either is zero (to avoid division by zero in inverse tests)
		if a.isZero() || b.isZero() {
			continue
		}

		// Test a + b - a = b
		var sum, diff Scalar
		sum.add(&a, &b)
		var negA Scalar
		negA.negate(&a)
		diff.add(&sum, &negA)

		if !diff.equal(&b) {
			t.Errorf("Random test %d: (a + b) - a should equal b", i)
		}

		// Test a * b / a = b (if a != 0)
		var product, quotient Scalar
		product.mul(&a, &b)
		var invA Scalar
		invA.inverse(&a)
		quotient.mul(&product, &invA)

		if !quotient.equal(&b) {
			t.Errorf("Random test %d: (a * b) / a should equal b", i)
		}
	}
}

func TestScalarEdgeCases(t *testing.T) {
	// Test group order boundary
	var n_minus_1 Scalar
	n_minus_1_bytes := [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
	}
	n_minus_1.setB32(n_minus_1_bytes[:])

	// Add 1 should give 0
	var one, result Scalar
	one.setInt(1)
	result.add(&n_minus_1, &one)

	if !result.isZero() {
		t.Error("(n-1) + 1 should equal 0 in scalar arithmetic")
	}

	// Test -1 = n-1
	var neg_one Scalar
	neg_one.negate(&one)

	if !neg_one.equal(&n_minus_1) {
		t.Error("-1 should equal n-1")
	}
}

// Benchmark tests
func BenchmarkScalarSetB32(b *testing.B) {
	var bytes [32]byte
	rand.Read(bytes[:])
	bytes[0] &= 0x7F // Ensure no overflow
	var s Scalar

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.setB32(bytes[:])
	}
}

func BenchmarkScalarAdd(b *testing.B) {
	var a, c, result Scalar
	a.setInt(12345)
	c.setInt(67890)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.add(&a, &c)
	}
}

func BenchmarkScalarMul(b *testing.B) {
	var a, c, result Scalar
	a.setInt(12345)
	c.setInt(67890)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.mul(&a, &c)
	}
}

func BenchmarkScalarInverse(b *testing.B) {
	var a, result Scalar
	a.setInt(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.inverse(&a)
	}
}

func BenchmarkScalarNegate(b *testing.B) {
	var a, result Scalar
	a.setInt(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.negate(&a)
	}
}
