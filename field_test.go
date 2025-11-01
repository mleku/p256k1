package p256k1

import (
	"crypto/rand"
	"testing"
)

// Test field element creation and basic operations
func TestFieldElementBasics(t *testing.T) {
	// Test zero element
	var zero FieldElement
	zero.setInt(0)
	if !zero.isZero() {
		t.Error("Zero element should be zero")
	}

	// Test one element
	var one FieldElement
	one.setInt(1)
	if one.isZero() {
		t.Error("One element should not be zero")
	}

	// Test normalization
	one.normalize()
	if !one.normalized {
		t.Error("Element should be normalized after normalize()")
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
				expected.setInt(0) // p - 1 mod p = 0
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
	neg.negate(&a, 1)
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
	// Test multiplication by small integers
	var a, result FieldElement
	a.setInt(3)
	result = a
	result.mulInt(4)
	result.normalize()

	var expected FieldElement
	expected.setInt(12)
	expected.normalize()

	if !result.equal(&expected) {
		t.Error("3 * 4 should equal 12")
	}

	// Test multiplication by zero
	result = a
	result.mulInt(0)
	result.normalize()

	if !result.isZero() {
		t.Error("a * 0 should equal zero")
	}
}

func TestFieldElementNormalization(t *testing.T) {
	var fe FieldElement
	fe.setInt(42)

	// Test weak normalization
	fe.normalizeWeak()
	if fe.magnitude != 1 {
		t.Error("Weak normalization should set magnitude to 1")
	}

	// Test full normalization
	fe.normalize()
	if !fe.normalized {
		t.Error("Full normalization should set normalized flag")
	}
	if fe.magnitude != 1 {
		t.Error("Full normalization should set magnitude to 1")
	}
}

func TestFieldElementOddness(t *testing.T) {
	// Test even number
	var even FieldElement
	even.setInt(42)
	even.normalize()
	if even.isOdd() {
		t.Error("42 should be even")
	}

	// Test odd number
	var odd FieldElement
	odd.setInt(43)
	odd.normalize()
	if !odd.isOdd() {
		t.Error("43 should be odd")
	}
}

func TestFieldElementConditionalMove(t *testing.T) {
	var a, b, result FieldElement
	a.setInt(10)
	b.setInt(20)
	result = a

	// Test conditional move with flag = 0 (no move)
	result.cmov(&b, 0)
	result.normalize()
	a.normalize()
	if !result.equal(&a) {
		t.Error("cmov with flag=0 should not change value")
	}

	// Test conditional move with flag = 1 (move)
	result = a
	result.cmov(&b, 1)
	result.normalize()
	b.normalize()
	if !result.equal(&b) {
		t.Error("cmov with flag=1 should change value")
	}
}

func TestFieldElementStorage(t *testing.T) {
	var fe FieldElement
	fe.setInt(12345)
	fe.normalize()

	// Test conversion to storage format
	var storage FieldElementStorage
	fe.toStorage(&storage)

	// Test conversion back from storage
	var restored FieldElement
	restored.fromStorage(&storage)

	if !fe.equal(&restored) {
		t.Error("Storage round-trip should preserve value")
	}
}

func TestFieldElementRandomOperations(t *testing.T) {
	// Test with random values
	for i := 0; i < 100; i++ {
		var bytes1, bytes2 [32]byte
		rand.Read(bytes1[:])
		rand.Read(bytes2[:])

		var a, b, sum, diff FieldElement
		a.setB32(bytes1[:])
		b.setB32(bytes2[:])

		// Test a + b - b = a
		sum = a
		sum.add(&b)
		diff = sum
		var negB FieldElement
		negB.negate(&b, b.magnitude)
		diff.add(&negB)
		diff.normalize()
		a.normalize()

		if !diff.equal(&a) {
			t.Errorf("Random test %d: (a + b) - b should equal a", i)
		}
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

// Benchmark tests
func BenchmarkFieldElementSetB32(b *testing.B) {
	var bytes [32]byte
	rand.Read(bytes[:])
	var fe FieldElement

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fe.setB32(bytes[:])
	}
}

func BenchmarkFieldElementNormalize(b *testing.B) {
	var fe FieldElement
	fe.setInt(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fe.normalize()
	}
}

func BenchmarkFieldElementAdd(b *testing.B) {
	var a, c FieldElement
	a.setInt(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.add(&a)
	}
}

func BenchmarkFieldElementMulInt(b *testing.B) {
	var fe FieldElement
	fe.setInt(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fe.mulInt(7)
	}
}

func BenchmarkFieldElementNegate(b *testing.B) {
	var a, result FieldElement
	a.setInt(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.negate(&a, 1)
	}
}
