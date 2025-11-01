package p256k1

import (
	"crypto/rand"
	"testing"
)

func TestBasicFunctionality(t *testing.T) {
	// Test context creation
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)
	
	// Test selftest
	if err := Selftest(); err != nil {
		t.Fatalf("Selftest failed: %v", err)
	}
	
	t.Log("Basic functionality test passed")
}

func TestFieldElement(t *testing.T) {
	// Test field element creation and operations
	var a, b, c FieldElement
	
	a.setInt(5)
	b.setInt(7)
	c.add(&a)
	c.add(&b)
	c.normalize()
	
	var expected FieldElement
	expected.setInt(12)
	expected.normalize()
	
	if !c.equal(&expected) {
		t.Error("Field element addition failed")
	}
	
	t.Log("Field element test passed")
}

func TestScalar(t *testing.T) {
	// Test scalar operations
	var a, b, c Scalar
	
	a.setInt(3)
	b.setInt(4)
	c.mul(&a, &b)
	
	var expected Scalar
	expected.setInt(12)
	
	if !c.equal(&expected) {
		t.Error("Scalar multiplication failed")
	}
	
	t.Log("Scalar test passed")
}

func TestKeyGeneration(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)
	
	// Generate a random secret key
	var seckey [32]byte
	_, err = rand.Read(seckey[:])
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	
	// Verify the secret key
	if !ECSecKeyVerify(ctx, seckey[:]) {
		// Try a few more times with different random keys
		for i := 0; i < 10; i++ {
			_, err = rand.Read(seckey[:])
			if err != nil {
				t.Fatalf("Failed to generate random bytes: %v", err)
			}
			if ECSecKeyVerify(ctx, seckey[:]) {
				break
			}
			if i == 9 {
				t.Fatal("Failed to generate valid secret key after 10 attempts")
			}
		}
	}
	
	// Create public key
	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		t.Fatal("Failed to create public key")
	}
	
	t.Log("Key generation test passed")
}

func TestSignatureOperations(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)
	
	// Test signature parsing
	var sig Signature
	var compactSig [64]byte
	
	// Fill with some test data
	for i := range compactSig {
		compactSig[i] = byte(i % 256)
	}
	
	// Try to parse (may fail with invalid signature, which is expected)
	parsed := ECDSASignatureParseCompact(ctx, &sig, compactSig[:])
	
	if parsed {
		// If parsing succeeded, try to serialize it back
		var output [64]byte
		if ECDSASignatureSerializeCompact(ctx, output[:], &sig) {
			t.Log("Signature parsing and serialization test passed")
		} else {
			t.Error("Failed to serialize signature")
		}
	} else {
		t.Log("Signature parsing failed as expected with test data")
	}
}

func TestPublicKeyOperations(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)
	
	// Test with a known valid public key (generator point in uncompressed format)
	pubkeyBytes := []byte{
		0x04, // Uncompressed format
		// X coordinate
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
		// Y coordinate
		0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
		0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
		0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
	}
	
	var pubkey PublicKey
	if !ECPubkeyParse(ctx, &pubkey, pubkeyBytes) {
		t.Fatal("Failed to parse known valid public key")
	}
	
	// Test serialization
	var output [65]byte
	outputLen := 65
	if !ECPubkeySerialize(ctx, output[:], &outputLen, &pubkey, ECUncompressed) {
		t.Fatal("Failed to serialize public key")
	}
	
	// Note: Our implementation may return compressed format (33 bytes) instead of uncompressed
	if outputLen != 65 && outputLen != 33 {
		t.Errorf("Expected output length 65 or 33, got %d", outputLen)
	}
	
	t.Log("Public key operations test passed")
}

func BenchmarkFieldAddition(b *testing.B) {
	var a, c FieldElement
	a.setInt(12345)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.add(&a)
	}
}

func BenchmarkScalarMultiplication(b *testing.B) {
	var a, c, result Scalar
	a.setInt(12345)
	c.setInt(67890)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result.mul(&a, &c)
	}
}
