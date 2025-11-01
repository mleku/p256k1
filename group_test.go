package p256k1

import (
	"testing"
)

func TestGroupElementAffine(t *testing.T) {
	// Test infinity point
	var inf GroupElementAffine
	inf.setInfinity()
	if !inf.isInfinity() {
		t.Error("setInfinity should create infinity point")
	}
	if !inf.isValid() {
		t.Error("infinity point should be valid")
	}

	// Test generator point
	if Generator.isInfinity() {
		t.Error("generator should not be infinity")
	}
	if !Generator.isValid() {
		t.Error("generator should be valid")
	}

	// Test point negation
	var neg GroupElementAffine
	neg.negate(&Generator)
	if neg.isInfinity() {
		t.Error("negated generator should not be infinity")
	}
	if !neg.isValid() {
		t.Error("negated generator should be valid")
	}

	// Test that G + (-G) = O (using Jacobian arithmetic)
	var gJac, negJac, result GroupElementJacobian
	gJac.setGE(&Generator)
	negJac.setGE(&neg)
	result.addVar(&gJac, &negJac)
	if !result.isInfinity() {
		t.Error("G + (-G) should equal infinity")
	}
}

func TestGroupElementJacobian(t *testing.T) {
	// Test conversion between affine and Jacobian
	var jac GroupElementJacobian
	var aff GroupElementAffine

	// Convert generator to Jacobian and back
	jac.setGE(&Generator)
	aff.setGEJ(&jac)
	
	if !aff.equal(&Generator) {
		t.Error("conversion G -> Jacobian -> affine should preserve point")
	}

	// Test point doubling
	var doubled GroupElementJacobian
	doubled.double(&jac)
	if doubled.isInfinity() {
		t.Error("2*G should not be infinity")
	}

	// Convert back to affine to validate
	var doubledAff GroupElementAffine
	doubledAff.setGEJ(&doubled)
	if !doubledAff.isValid() {
		t.Error("2*G should be valid point")
	}
}

func TestGroupElementStorage(t *testing.T) {
	// Test storage conversion
	var storage GroupElementStorage
	var restored GroupElementAffine

	// Store and restore generator
	Generator.toStorage(&storage)
	restored.fromStorage(&storage)

	if !restored.equal(&Generator) {
		t.Error("storage conversion should preserve point")
	}

	// Test infinity storage
	var inf GroupElementAffine
	inf.setInfinity()
	inf.toStorage(&storage)
	restored.fromStorage(&storage)

	if !restored.isInfinity() {
		t.Error("infinity should be preserved in storage")
	}
}

func TestGroupElementBytes(t *testing.T) {
	var buf [64]byte
	var restored GroupElementAffine

	// Test generator conversion
	Generator.toBytes(buf[:])
	restored.fromBytes(buf[:])

	if !restored.equal(&Generator) {
		t.Error("byte conversion should preserve point")
	}

	// Test infinity conversion
	var inf GroupElementAffine
	inf.setInfinity()
	inf.toBytes(buf[:])
	restored.fromBytes(buf[:])

	if !restored.isInfinity() {
		t.Error("infinity should be preserved in byte conversion")
	}
}

func BenchmarkGroupDouble(b *testing.B) {
	var jac GroupElementJacobian
	jac.setGE(&Generator)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jac.double(&jac)
	}
}

func BenchmarkGroupAdd(b *testing.B) {
	var jac1, jac2 GroupElementJacobian
	jac1.setGE(&Generator)
	jac2.setGE(&Generator)
	jac2.double(&jac2) // Make it 2*G

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jac1.addVar(&jac1, &jac2)
	}
}
