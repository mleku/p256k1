package p256k1

import (
	"testing"
)

func TestGroupElementBasics(t *testing.T) {
	// Test infinity point
	var inf GroupElementAffine
	inf.setInfinity()
	if !inf.isInfinity() {
		t.Error("Infinity point should be infinity")
	}

	// Test generator point
	gen := GeneratorAffine
	if gen.isInfinity() {
		t.Error("Generator should not be infinity")
	}

	// Test validity
	if !gen.isValid() {
		t.Error("Generator should be valid")
	}
}

func TestGroupElementNegation(t *testing.T) {
	// Test negation of generator
	gen := GeneratorAffine
	var negGen GroupElementAffine
	negGen.negate(&gen)

	if negGen.isInfinity() {
		t.Error("Negation of generator should not be infinity")
	}

	// Test double negation
	var doubleNeg GroupElementAffine
	doubleNeg.negate(&negGen)

	if !doubleNeg.equal(&gen) {
		t.Error("Double negation should return original point")
	}

	// Test negation of infinity
	var inf, negInf GroupElementAffine
	inf.setInfinity()
	negInf.negate(&inf)

	if !negInf.isInfinity() {
		t.Error("Negation of infinity should be infinity")
	}
}

func TestGroupElementSetXY(t *testing.T) {
	// Test setting coordinates
	var point GroupElementAffine
	var x, y FieldElement
	x.setInt(1)
	y.setInt(1)

	point.setXY(&x, &y)

	if point.isInfinity() {
		t.Error("Point with coordinates should not be infinity")
	}

	// Test that coordinates are preserved
	if !point.x.equal(&x) {
		t.Error("X coordinate should be preserved")
	}
	if !point.y.equal(&y) {
		t.Error("Y coordinate should be preserved")
	}
}

func TestGroupElementSetXOVar(t *testing.T) {
	// Test setting from X coordinate and oddness
	var x FieldElement
	x.setInt(1) // This may not be on the curve, but test the function

	var point GroupElementAffine
	// Try both odd and even Y
	success := point.setXOVar(&x, false)
	if success && point.isInfinity() {
		t.Error("Successfully created point should not be infinity")
	}

	success = point.setXOVar(&x, true)
	if success && point.isInfinity() {
		t.Error("Successfully created point should not be infinity")
	}
}

func TestGroupElementEquality(t *testing.T) {
	// Test equality with same point
	gen := GeneratorAffine
	var gen2 GroupElementAffine
	gen2 = gen

	if !gen.equal(&gen2) {
		t.Error("Same points should be equal")
	}

	// Test inequality with different points
	var negGen GroupElementAffine
	negGen.negate(&gen)

	if gen.equal(&negGen) {
		t.Error("Generator and its negation should not be equal")
	}

	// Test equality of infinity points
	var inf1, inf2 GroupElementAffine
	inf1.setInfinity()
	inf2.setInfinity()

	if !inf1.equal(&inf2) {
		t.Error("Two infinity points should be equal")
	}

	// Test inequality between infinity and non-infinity
	if gen.equal(&inf1) {
		t.Error("Generator and infinity should not be equal")
	}
}

func TestGroupElementJacobianBasics(t *testing.T) {
	// Test infinity
	var inf GroupElementJacobian
	inf.setInfinity()
	if !inf.isInfinity() {
		t.Error("Jacobian infinity should be infinity")
	}

	// Test conversion from affine
	gen := GeneratorAffine
	var genJ GroupElementJacobian
	genJ.setGE(&gen)

	if genJ.isInfinity() {
		t.Error("Jacobian generator should not be infinity")
	}

	// Test conversion back to affine
	var genBack GroupElementAffine
	genBack.setGEJ(&genJ)

	if !genBack.equal(&gen) {
		t.Error("Round-trip conversion should preserve point")
	}
}

func TestGroupElementJacobianDoubling(t *testing.T) {
	// Test point doubling
	gen := GeneratorAffine
	var genJ GroupElementJacobian
	genJ.setGE(&gen)

	var doubled GroupElementJacobian
	doubled.double(&genJ)

	if doubled.isInfinity() {
		t.Error("Doubled generator should not be infinity")
	}

	// Test doubling infinity
	var inf, doubledInf GroupElementJacobian
	inf.setInfinity()
	doubledInf.double(&inf)

	if !doubledInf.isInfinity() {
		t.Error("Doubled infinity should be infinity")
	}

	// Test that 2*P != P (for non-zero points)
	var doubledAffine GroupElementAffine
	doubledAffine.setGEJ(&doubled)

	if doubledAffine.equal(&gen) {
		t.Error("2*G should not equal G")
	}
}

func TestGroupElementJacobianAddition(t *testing.T) {
	// Test P + O = P (where O is infinity)
	gen := GeneratorAffine
	var genJ GroupElementJacobian
	genJ.setGE(&gen)

	var inf GroupElementJacobian
	inf.setInfinity()

	var result GroupElementJacobian
	result.addVar(&genJ, &inf)

	var resultAffine GroupElementAffine
	resultAffine.setGEJ(&result)

	if !resultAffine.equal(&gen) {
		t.Error("P + O should equal P")
	}

	// Test O + P = P
	result.addVar(&inf, &genJ)
	resultAffine.setGEJ(&result)

	if !resultAffine.equal(&gen) {
		t.Error("O + P should equal P")
	}

	// Test P + (-P) = O
	var negGen GroupElementAffine
	negGen.negate(&gen)
	var negGenJ GroupElementJacobian
	negGenJ.setGE(&negGen)

	result.addVar(&genJ, &negGenJ)

	if !result.isInfinity() {
		t.Error("P + (-P) should equal infinity")
	}

	// Test P + P = 2P (should equal doubling)
	var sum, doubled GroupElementJacobian
	sum.addVar(&genJ, &genJ)
	doubled.double(&genJ)

	var sumAffine, doubledAffine GroupElementAffine
	sumAffine.setGEJ(&sum)
	doubledAffine.setGEJ(&doubled)

	if !sumAffine.equal(&doubledAffine) {
		t.Error("P + P should equal 2*P")
	}
}

func TestGroupElementAddGE(t *testing.T) {
	// Test mixed addition (Jacobian + Affine)
	gen := GeneratorAffine
	var genJ GroupElementJacobian
	genJ.setGE(&gen)

	var negGen GroupElementAffine
	negGen.negate(&gen)

	var result GroupElementJacobian
	result.addGE(&genJ, &negGen)

	if !result.isInfinity() {
		t.Error("P + (-P) should equal infinity in mixed addition")
	}

	// Test adding infinity
	var inf GroupElementAffine
	inf.setInfinity()

	result.addGE(&genJ, &inf)
	var resultAffine GroupElementAffine
	resultAffine.setGEJ(&result)

	if !resultAffine.equal(&gen) {
		t.Error("P + O should equal P in mixed addition")
	}
}

func TestGroupElementNegationJacobian(t *testing.T) {
	// Test Jacobian negation
	gen := GeneratorAffine
	var genJ GroupElementJacobian
	genJ.setGE(&gen)

	var negGenJ GroupElementJacobian
	negGenJ.negate(&genJ)

	if negGenJ.isInfinity() {
		t.Error("Negated Jacobian point should not be infinity")
	}

	// Convert back to affine and compare
	var negGenAffine, expectedNegAffine GroupElementAffine
	negGenAffine.setGEJ(&negGenJ)
	expectedNegAffine.negate(&gen)

	if !negGenAffine.equal(&expectedNegAffine) {
		t.Error("Jacobian negation should match affine negation")
	}
}

func TestGroupElementStorage(t *testing.T) {
	// Test storage conversion
	gen := GeneratorAffine
	var storage GroupElementStorage
	gen.toStorage(&storage)

	var restored GroupElementAffine
	restored.fromStorage(&storage)

	if !restored.equal(&gen) {
		t.Error("Storage round-trip should preserve point")
	}
}

func TestGroupElementBytes(t *testing.T) {
	// Test byte conversion
	gen := GeneratorAffine
	var bytes [64]byte
	gen.toBytes(bytes[:])

	var restored GroupElementAffine
	restored.fromBytes(bytes[:])

	if !restored.equal(&gen) {
		t.Error("Byte round-trip should preserve point")
	}
}

func TestGroupElementClear(t *testing.T) {
	// Test clearing affine point
	gen := GeneratorAffine
	gen.clear()

	if !gen.isInfinity() {
		t.Error("Cleared affine point should be infinity")
	}

	// Test clearing Jacobian point
	var genJ GroupElementJacobian
	genJ.setGE(&GeneratorAffine)
	genJ.clear()

	if !genJ.isInfinity() {
		t.Error("Cleared Jacobian point should be infinity")
	}
}

func TestGroupElementRandomOperations(t *testing.T) {
	// Test with random scalar multiplications (simplified)
	gen := GeneratorAffine
	var genJ GroupElementJacobian
	genJ.setGE(&gen)

	// Test associativity: (P + P) + P = P + (P + P)
	var p_plus_p, left, right GroupElementJacobian
	p_plus_p.addVar(&genJ, &genJ)
	left.addVar(&p_plus_p, &genJ)
	right.addVar(&genJ, &p_plus_p)

	var leftAffine, rightAffine GroupElementAffine
	leftAffine.setGEJ(&left)
	rightAffine.setGEJ(&right)

	if !leftAffine.equal(&rightAffine) {
		t.Error("Addition should be associative")
	}

	// Test commutativity: P + Q = Q + P
	var doubled GroupElementJacobian
	doubled.double(&genJ)

	var sum1, sum2 GroupElementJacobian
	sum1.addVar(&genJ, &doubled)
	sum2.addVar(&doubled, &genJ)

	var sum1Affine, sum2Affine GroupElementAffine
	sum1Affine.setGEJ(&sum1)
	sum2Affine.setGEJ(&sum2)

	if !sum1Affine.equal(&sum2Affine) {
		t.Error("Addition should be commutative")
	}
}

func TestGroupElementEdgeCases(t *testing.T) {
	// Test operations with infinity
	var inf GroupElementAffine
	inf.setInfinity()

	// Test negation of infinity
	var negInf GroupElementAffine
	negInf.negate(&inf)
	if !negInf.isInfinity() {
		t.Error("Negation of infinity should be infinity")
	}

	// Test setting infinity to coordinates (should remain infinity)
	var x, y FieldElement
	x.setInt(0)
	y.setInt(0)
	inf.setXY(&x, &y)
	if inf.isInfinity() {
		t.Error("Setting coordinates should make point non-infinity")
	}

	// Reset to infinity for next test
	inf.setInfinity()

	// Test conversion of infinity to Jacobian
	var infJ GroupElementJacobian
	infJ.setGE(&inf)
	if !infJ.isInfinity() {
		t.Error("Jacobian conversion of infinity should be infinity")
	}

	// Test conversion back
	var infBack GroupElementAffine
	infBack.setGEJ(&infJ)
	if !infBack.isInfinity() {
		t.Error("Affine conversion of Jacobian infinity should be infinity")
	}
}

func TestGroupElementMultipleDoubling(t *testing.T) {
	// Test multiple doublings: 2^n * G
	gen := GeneratorAffine
	var current GroupElementJacobian
	current.setGE(&gen)

	var powers [8]GroupElementAffine
	powers[0] = gen

	// Compute 2^i * G for i = 1..7
	for i := 1; i < 8; i++ {
		current.double(&current)
		powers[i].setGEJ(&current)

		if powers[i].isInfinity() {
			t.Errorf("2^%d * G should not be infinity", i)
		}

		// Check that each power is different from previous ones
		for j := 0; j < i; j++ {
			if powers[i].equal(&powers[j]) {
				t.Errorf("2^%d * G should not equal 2^%d * G", i, j)
			}
		}
	}
}

// Benchmark tests
func BenchmarkGroupElementDouble(b *testing.B) {
	gen := GeneratorAffine
	var genJ, result GroupElementJacobian
	genJ.setGE(&gen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.double(&genJ)
	}
}

func BenchmarkGroupElementAddVar(b *testing.B) {
	gen := GeneratorAffine
	var genJ, doubled, result GroupElementJacobian
	genJ.setGE(&gen)
	doubled.double(&genJ)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.addVar(&genJ, &doubled)
	}
}

func BenchmarkGroupElementAddGE(b *testing.B) {
	gen := GeneratorAffine
	var genJ, result GroupElementJacobian
	genJ.setGE(&gen)

	var negGen GroupElementAffine
	negGen.negate(&gen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.addGE(&genJ, &negGen)
	}
}

func BenchmarkGroupElementSetGEJ(b *testing.B) {
	gen := GeneratorAffine
	var genJ GroupElementJacobian
	genJ.setGE(&gen)

	var result GroupElementAffine

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.setGEJ(&genJ)
	}
}

func BenchmarkGroupElementNegate(b *testing.B) {
	gen := GeneratorAffine
	var result GroupElementAffine

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.negate(&gen)
	}
}
