package p256k1

import (
	"testing"
)

func TestFieldElementBasics(t *testing.T) {
	// Test zero field element
	var zero FieldElement
	zero.setInt(0)
	zero.normalize()
	if !zero.isZero() {
		t.Error("Zero field element should be zero")
	}

	// Test one field element
	var one FieldElement
	one.setInt(1)
	one.normalize()
	if one.isZero() {
		t.Error("One field element should not be zero")
	}

	// Test equality
	var one2 FieldElement
	one2.setInt(1)
	one2.normalize()
	if !one.equal(&one2) {
		t.Error("Two normalized ones should be equal")
	}
}

func TestFieldElementSetB32(t *testing.T) {
	// Test setting from 32-byte array
	testCases := []struct {
		name  string
		bytes [32]byte
	}{
		{
			name:  "zero",
			bytes: [32]byte{},
		},
		{
			name:  "one",
			bytes: [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name:  "max_value",
			bytes: [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var fe FieldElement
			fe.setB32(tc.bytes[:])

			// Test round-trip
			var result [32]byte
			fe.normalize()
			fe.getB32(result[:])

			// For field modulus reduction, we need to check if the result is valid
			if tc.name == "max_value" {
				// This should be reduced modulo p
				var expected FieldElement
				expected.setInt(0) // p mod p = 0
				expected.normalize()
				if !fe.equal(&expected) {
					t.Error("Field modulus should reduce to zero")
				}
			}
		})
	}
}

func TestFieldElementArithmetic(t *testing.T) {
	// Test addition
	var a, b, c FieldElement
	a.setInt(5)
	b.setInt(7)
	c = a
	c.add(&b)
	c.normalize()

	var expected FieldElement
	expected.setInt(12)
	expected.normalize()
	if !c.equal(&expected) {
		t.Error("5 + 7 should equal 12")
	}

	// Test negation
	var neg FieldElement
	neg.negate(&a, a.magnitude)
	neg.normalize()

	var sum FieldElement
	sum = a
	sum.add(&neg)
	sum.normalize()

	if !sum.isZero() {
		t.Error("a + (-a) should equal zero")
	}
}

func TestFieldElementMultiplication(t *testing.T) {
	// Test multiplication
	var a, b, c FieldElement
	a.setInt(5)
	b.setInt(7)
	c.mul(&a, &b)
	c.normalize()

	var expected FieldElement
	expected.setInt(35)
	expected.normalize()
	if !c.equal(&expected) {
		t.Error("5 * 7 should equal 35")
	}

	// Test squaring
	var sq FieldElement
	sq.sqr(&a)
	sq.normalize()

	expected.setInt(25)
	expected.normalize()
	if !sq.equal(&expected) {
		t.Error("5^2 should equal 25")
	}
}

func TestFieldElementNormalization(t *testing.T) {
	var fe FieldElement
	fe.setInt(42)

	// Before normalization
	if fe.normalized {
		fe.normalized = false // Force non-normalized state
	}

	// After normalization
	fe.normalize()
	if !fe.normalized {
		t.Error("Field element should be normalized after normalize()")
	}
	if fe.magnitude != 1 {
		t.Error("Normalized field element should have magnitude 1")
	}
}

func TestFieldElementOddness(t *testing.T) {
	var even, odd FieldElement
	even.setInt(4)
	even.normalize()
	odd.setInt(5)
	odd.normalize()

	if even.isOdd() {
		t.Error("4 should be even")
	}
	if !odd.isOdd() {
		t.Error("5 should be odd")
	}
}

func TestFieldElementConditionalMove(t *testing.T) {
	var a, b, original FieldElement
	a.setInt(5)
	b.setInt(10)
	original = a

	// Test conditional move with flag = 0
	a.cmov(&b, 0)
	if !a.equal(&original) {
		t.Error("Conditional move with flag=0 should not change value")
	}

	// Test conditional move with flag = 1
	a.cmov(&b, 1)
	if !a.equal(&b) {
		t.Error("Conditional move with flag=1 should copy value")
	}
}

func TestFieldElementStorage(t *testing.T) {
	var fe FieldElement
	fe.setInt(12345)
	fe.normalize()

	// Convert to storage
	var storage FieldElementStorage
	fe.toStorage(&storage)

	// Convert back
	var restored FieldElement
	restored.fromStorage(&storage)
	restored.normalize()

	if !fe.equal(&restored) {
		t.Error("Storage round-trip should preserve value")
	}
}

func TestFieldElementEdgeCases(t *testing.T) {
	// Test field modulus boundary
	// Set to p-1 (field modulus minus 1)
	// p-1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E
	p_minus_1 := [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
	}

	var fe FieldElement
	fe.setB32(p_minus_1[:])
	fe.normalize()

	// Add 1 should give 0
	var one FieldElement
	one.setInt(1)
	fe.add(&one)
	fe.normalize()

	if !fe.isZero() {
		t.Error("(p-1) + 1 should equal 0 in field arithmetic")
	}
}

func TestFieldElementClear(t *testing.T) {
	var fe FieldElement
	fe.setInt(12345)

	fe.clear()

	// After clearing, should be zero and normalized
	if !fe.isZero() {
		t.Error("Cleared field element should be zero")
	}
	if !fe.normalized {
		t.Error("Cleared field element should be normalized")
	}
}
