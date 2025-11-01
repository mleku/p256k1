package p256k1

import (
	"crypto/rand"
	"testing"
)

func TestOptimizedScalarMultiplication(t *testing.T) {
	// Test optimized generator multiplication
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)
	
	// Test with known scalar
	var scalar Scalar
	scalar.setInt(12345)
	
	var result GroupElementJacobian
	ecmultGen(&ctx.ecmultGenCtx, &result, &scalar)
	
	if result.isInfinity() {
		t.Error("Generator multiplication should not result in infinity for non-zero scalar")
	}
	
	t.Log("Optimized generator multiplication test passed")
}

func TestEcmultConst(t *testing.T) {
	// Test constant-time scalar multiplication
	var point GroupElementAffine
	point = GeneratorAffine // Use generator as test point
	
	var scalar Scalar
	scalar.setInt(7)
	
	var result GroupElementJacobian
	EcmultConst(&result, &scalar, &point)
	
	if result.isInfinity() {
		t.Error("Constant-time multiplication should not result in infinity for non-zero inputs")
	}
	
	t.Log("Constant-time multiplication test passed")
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
	
	t.Log("Multi-scalar multiplication test passed")
}

func TestHashFunctions(t *testing.T) {
	// Test SHA-256
	input := []byte("test message")
	var output [32]byte
	
	SHA256Simple(output[:], input)
	
	// Verify output is not all zeros
	allZero := true
	for _, b := range output {
		if b != 0 {
			allZero = false
			break
		}
	}
	
	if allZero {
		t.Error("SHA-256 output should not be all zeros")
	}
	
	t.Log("SHA-256 test passed")
}

func TestTaggedSHA256(t *testing.T) {
	// Test tagged SHA-256 (BIP-340)
	tag := []byte("BIP0340/challenge")
	msg := []byte("test message")
	var output [32]byte
	
	TaggedSHA256(output[:], tag, msg)
	
	// Verify output is not all zeros
	allZero := true
	for _, b := range output {
		if b != 0 {
			allZero = false
			break
		}
	}
	
	if allZero {
		t.Error("Tagged SHA-256 output should not be all zeros")
	}
	
	t.Log("Tagged SHA-256 test passed")
}

func TestRFC6979Nonce(t *testing.T) {
	// Test RFC 6979 nonce generation
	var msg32, key32, nonce32 [32]byte
	
	// Fill with test data
	for i := range msg32 {
		msg32[i] = byte(i)
		key32[i] = byte(i + 1)
	}
	
	// Generate nonce
	success := rfc6979NonceFunction(nonce32[:], msg32[:], key32[:], nil, nil, 0)
	if !success {
		t.Error("RFC 6979 nonce generation failed")
	}
	
	// Verify nonce is not all zeros
	allZero := true
	for _, b := range nonce32 {
		if b != 0 {
			allZero = false
			break
		}
	}
	
	if allZero {
		t.Error("RFC 6979 nonce should not be all zeros")
	}
	
	// Test determinism - same inputs should produce same nonce
	var nonce32_2 [32]byte
	success2 := rfc6979NonceFunction(nonce32_2[:], msg32[:], key32[:], nil, nil, 0)
	if !success2 {
		t.Error("Second RFC 6979 nonce generation failed")
	}
	
	for i := range nonce32 {
		if nonce32[i] != nonce32_2[i] {
			t.Error("RFC 6979 nonce generation is not deterministic")
			break
		}
	}
	
	t.Log("RFC 6979 nonce generation test passed")
}

func TestContextBlinding(t *testing.T) {
	// Test context blinding for side-channel protection
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)
	
	// Generate random seed
	var seed [32]byte
	_, err = rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate random seed: %v", err)
	}
	
	// Apply blinding
	err = ContextRandomize(ctx, seed[:])
	if err != nil {
		t.Errorf("Context randomization failed: %v", err)
	}
	
	// Test that blinded context still works
	var seckey [32]byte
	_, err = rand.Read(seckey[:])
	if err != nil {
		t.Fatalf("Failed to generate random secret key: %v", err)
	}
	
	// Ensure valid secret key
	for i := 0; i < 10; i++ {
		if ECSecKeyVerify(ctx, seckey[:]) {
			break
		}
		_, err = rand.Read(seckey[:])
		if err != nil {
			t.Fatalf("Failed to generate random secret key: %v", err)
		}
		if i == 9 {
			t.Fatal("Failed to generate valid secret key after 10 attempts")
		}
	}
	
	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		t.Error("Key generation failed with blinded context")
	}
	
	t.Log("Context blinding test passed")
}

func BenchmarkOptimizedEcmultGen(b *testing.B) {
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

func BenchmarkSHA256(b *testing.B) {
	input := []byte("test message for benchmarking SHA-256 performance")
	var output [32]byte
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SHA256Simple(output[:], input)
	}
}

func BenchmarkTaggedSHA256(b *testing.B) {
	tag := []byte("BIP0340/challenge")
	msg := []byte("test message for benchmarking tagged SHA-256 performance")
	var output [32]byte
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		TaggedSHA256(output[:], tag, msg)
	}
}

func BenchmarkRFC6979Nonce(b *testing.B) {
	var msg32, key32, nonce32 [32]byte
	
	// Fill with test data
	for i := range msg32 {
		msg32[i] = byte(i)
		key32[i] = byte(i + 1)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rfc6979NonceFunction(nonce32[:], msg32[:], key32[:], nil, nil, 0)
	}
}
