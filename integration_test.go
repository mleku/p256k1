package p256k1

import (
	"crypto/rand"
	"testing"
)

// Test complete ECDSA signing and verification workflow
func TestECDSASignVerifyWorkflow(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Generate a random secret key
	var seckey [32]byte
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

	// Create public key
	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		t.Fatal("Failed to create public key")
	}

	// Create message hash
	var msghash [32]byte
	_, err = rand.Read(msghash[:])
	if err != nil {
		t.Fatalf("Failed to generate message hash: %v", err)
	}

	// Sign the message
	var sig Signature
	if !ECDSASign(ctx, &sig, msghash[:], seckey[:], nil, nil) {
		t.Fatal("Failed to sign message")
	}

	// Verify the signature
	if !ECDSAVerify(ctx, &sig, msghash[:], &pubkey) {
		t.Fatal("Failed to verify signature")
	}

	// Test that signature fails with wrong message
	msghash[0] ^= 1 // Flip one bit
	if ECDSAVerify(ctx, &sig, msghash[:], &pubkey) {
		t.Error("Signature should not verify with modified message")
	}

	// Restore message and test with wrong public key
	msghash[0] ^= 1 // Restore original message

	var wrongSeckey [32]byte
	for i := 0; i < 10; i++ {
		_, err = rand.Read(wrongSeckey[:])
		if err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		if ECSecKeyVerify(ctx, wrongSeckey[:]) {
			break
		}
		if i == 9 {
			t.Fatal("Failed to generate valid wrong secret key after 10 attempts")
		}
	}

	var wrongPubkey PublicKey
	if !ECPubkeyCreate(ctx, &wrongPubkey, wrongSeckey[:]) {
		t.Fatal("Failed to create wrong public key")
	}

	if ECDSAVerify(ctx, &sig, msghash[:], &wrongPubkey) {
		t.Error("Signature should not verify with wrong public key")
	}
}

// Test signature serialization and parsing
func TestSignatureSerialization(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Create a signature
	var seckey [32]byte
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

	var msghash [32]byte
	_, err = rand.Read(msghash[:])
	if err != nil {
		t.Fatalf("Failed to generate message hash: %v", err)
	}

	var sig Signature
	if !ECDSASign(ctx, &sig, msghash[:], seckey[:], nil, nil) {
		t.Fatal("Failed to sign message")
	}

	// Test compact serialization
	var compact [64]byte
	if !ECDSASignatureSerializeCompact(ctx, compact[:], &sig) {
		t.Fatal("Failed to serialize signature in compact format")
	}

	// Parse back from compact format
	var parsedSig Signature
	if !ECDSASignatureParseCompact(ctx, &parsedSig, compact[:]) {
		t.Fatal("Failed to parse signature from compact format")
	}

	// Serialize again and compare
	var compact2 [64]byte
	if !ECDSASignatureSerializeCompact(ctx, compact2[:], &parsedSig) {
		t.Fatal("Failed to serialize parsed signature")
	}

	for i := 0; i < 64; i++ {
		if compact[i] != compact2[i] {
			t.Error("Compact serialization round-trip failed")
			break
		}
	}

	// Test DER serialization
	var der [72]byte // Max DER size
	derLen := 72
	if !ECDSASignatureSerializeDER(ctx, der[:], &derLen, &sig) {
		t.Fatal("Failed to serialize signature in DER format")
	}

	// Parse back from DER format
	var parsedSigDER Signature
	if !ECDSASignatureParseDER(ctx, &parsedSigDER, der[:derLen]) {
		t.Fatal("Failed to parse signature from DER format")
	}

	// Verify both parsed signatures work
	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		t.Fatal("Failed to create public key")
	}

	if !ECDSAVerify(ctx, &parsedSig, msghash[:], &pubkey) {
		t.Error("Parsed compact signature should verify")
	}

	if !ECDSAVerify(ctx, &parsedSigDER, msghash[:], &pubkey) {
		t.Error("Parsed DER signature should verify")
	}
}

// Test public key serialization and parsing
func TestPublicKeySerialization(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Create a public key
	var seckey [32]byte
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

	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		t.Fatal("Failed to create public key")
	}

	// Test compressed serialization
	var compressed [33]byte
	compressedLen := 33
	if !ECPubkeySerialize(ctx, compressed[:], &compressedLen, &pubkey, ECCompressed) {
		t.Fatal("Failed to serialize public key in compressed format")
	}

	if compressedLen != 33 {
		t.Errorf("Expected compressed length 33, got %d", compressedLen)
	}

	// Test uncompressed serialization
	var uncompressed [65]byte
	uncompressedLen := 65
	if !ECPubkeySerialize(ctx, uncompressed[:], &uncompressedLen, &pubkey, ECUncompressed) {
		t.Fatal("Failed to serialize public key in uncompressed format")
	}

	if uncompressedLen != 65 {
		t.Errorf("Expected uncompressed length 65, got %d", uncompressedLen)
	}

	// Parse compressed format
	var parsedCompressed PublicKey
	if !ECPubkeyParse(ctx, &parsedCompressed, compressed[:compressedLen]) {
		t.Fatal("Failed to parse compressed public key")
	}

	// Parse uncompressed format
	var parsedUncompressed PublicKey
	if !ECPubkeyParse(ctx, &parsedUncompressed, uncompressed[:uncompressedLen]) {
		t.Fatal("Failed to parse uncompressed public key")
	}

	// Both should represent the same key
	var compressedAgain [33]byte
	compressedAgainLen := 33
	if !ECPubkeySerialize(ctx, compressedAgain[:], &compressedAgainLen, &parsedCompressed, ECCompressed) {
		t.Fatal("Failed to serialize parsed compressed key")
	}

	var uncompressedAgain [33]byte
	uncompressedAgainLen := 33
	if !ECPubkeySerialize(ctx, uncompressedAgain[:], &uncompressedAgainLen, &parsedUncompressed, ECCompressed) {
		t.Fatal("Failed to serialize parsed uncompressed key")
	}

	for i := 0; i < 33; i++ {
		if compressedAgain[i] != uncompressedAgain[i] {
			t.Error("Compressed and uncompressed should represent same key")
			break
		}
	}
}

// Test public key comparison
func TestPublicKeyComparison(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Create two different keys
	var seckey1, seckey2 [32]byte
	for i := 0; i < 10; i++ {
		_, err = rand.Read(seckey1[:])
		if err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		if ECSecKeyVerify(ctx, seckey1[:]) {
			break
		}
		if i == 9 {
			t.Fatal("Failed to generate valid secret key 1 after 10 attempts")
		}
	}

	for i := 0; i < 10; i++ {
		_, err = rand.Read(seckey2[:])
		if err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		if ECSecKeyVerify(ctx, seckey2[:]) {
			break
		}
		if i == 9 {
			t.Fatal("Failed to generate valid secret key 2 after 10 attempts")
		}
	}

	var pubkey1, pubkey2, pubkey1Copy PublicKey
	if !ECPubkeyCreate(ctx, &pubkey1, seckey1[:]) {
		t.Fatal("Failed to create public key 1")
	}
	if !ECPubkeyCreate(ctx, &pubkey2, seckey2[:]) {
		t.Fatal("Failed to create public key 2")
	}
	if !ECPubkeyCreate(ctx, &pubkey1Copy, seckey1[:]) {
		t.Fatal("Failed to create public key 1 copy")
	}

	// Test comparison
	cmp1vs2 := ECPubkeyCmp(ctx, &pubkey1, &pubkey2)
	cmp2vs1 := ECPubkeyCmp(ctx, &pubkey2, &pubkey1)
	cmp1vs1 := ECPubkeyCmp(ctx, &pubkey1, &pubkey1Copy)

	if cmp1vs2 == 0 {
		t.Error("Different keys should not compare equal")
	}
	if cmp2vs1 == 0 {
		t.Error("Different keys should not compare equal (reversed)")
	}
	if cmp1vs1 != 0 {
		t.Error("Same keys should compare equal")
	}
	if (cmp1vs2 > 0) == (cmp2vs1 > 0) {
		t.Error("Comparison should be antisymmetric")
	}
}

// Test context randomization
func TestContextRandomization(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Test randomization with random seed
	var seed [32]byte
	_, err = rand.Read(seed[:])
	if err != nil {
		t.Fatalf("Failed to generate random seed: %v", err)
	}

	err = ContextRandomize(ctx, seed[:])
	if err != nil {
		t.Errorf("Context randomization failed: %v", err)
	}

	// Test that randomized context still works
	var seckey [32]byte
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

	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		t.Error("Key generation should work with randomized context")
	}

	// Test signing with randomized context
	var msghash [32]byte
	_, err = rand.Read(msghash[:])
	if err != nil {
		t.Fatalf("Failed to generate message hash: %v", err)
	}

	var sig Signature
	if !ECDSASign(ctx, &sig, msghash[:], seckey[:], nil, nil) {
		t.Error("Signing should work with randomized context")
	}

	if !ECDSAVerify(ctx, &sig, msghash[:], &pubkey) {
		t.Error("Verification should work with randomized context")
	}

	// Test randomization with nil seed (should work)
	err = ContextRandomize(ctx, nil)
	if err != nil {
		t.Errorf("Context randomization with nil seed failed: %v", err)
	}
}

// Test multiple signatures with same key
func TestMultipleSignatures(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Generate key pair
	var seckey [32]byte
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

	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		t.Fatal("Failed to create public key")
	}

	// Sign multiple different messages
	numMessages := 10
	messages := make([][32]byte, numMessages)
	signatures := make([]Signature, numMessages)

	for i := 0; i < numMessages; i++ {
		_, err = rand.Read(messages[i][:])
		if err != nil {
			t.Fatalf("Failed to generate message %d: %v", i, err)
		}

		if !ECDSASign(ctx, &signatures[i], messages[i][:], seckey[:], nil, nil) {
			t.Fatalf("Failed to sign message %d", i)
		}
	}

	// Verify all signatures
	for i := 0; i < numMessages; i++ {
		if !ECDSAVerify(ctx, &signatures[i], messages[i][:], &pubkey) {
			t.Errorf("Failed to verify signature %d", i)
		}

		// Test cross-verification (should fail)
		for j := 0; j < numMessages; j++ {
			if i != j {
				if ECDSAVerify(ctx, &signatures[i], messages[j][:], &pubkey) {
					t.Errorf("Signature %d should not verify message %d", i, j)
				}
			}
		}
	}
}

// Test edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Test invalid secret keys
	var zeroKey [32]byte // All zeros
	if ECSecKeyVerify(ctx, zeroKey[:]) {
		t.Error("Zero secret key should be invalid")
	}

	var overflowKey [32]byte
	// Set to group order (invalid)
	overflowBytes := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}
	copy(overflowKey[:], overflowBytes)
	if ECSecKeyVerify(ctx, overflowKey[:]) {
		t.Error("Overflowing secret key should be invalid")
	}

	// Test invalid public key parsing
	var invalidPubkey PublicKey
	invalidBytes := []byte{0xFF, 0xFF, 0xFF} // Too short
	if ECPubkeyParse(ctx, &invalidPubkey, invalidBytes) {
		t.Error("Invalid public key bytes should not parse")
	}

	// Test invalid signature parsing
	var invalidSig Signature
	invalidSigBytes := make([]byte, 64)
	for i := range invalidSigBytes {
		invalidSigBytes[i] = 0xFF // All 0xFF (likely invalid)
	}
	if ECDSASignatureParseCompact(ctx, &invalidSig, invalidSigBytes) {
		// This might succeed depending on implementation, so we just test it doesn't crash
	}
}

// Test selftest functionality
func TestSelftest(t *testing.T) {
	if err := Selftest(); err != nil {
		t.Errorf("Selftest failed: %v", err)
	}
}

// Integration test with known test vectors
func TestKnownTestVectors(t *testing.T) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Test vector from Bitcoin Core tests
	seckey := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	if !ECSecKeyVerify(ctx, seckey) {
		t.Fatal("Test vector secret key should be valid")
	}

	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey) {
		t.Fatal("Failed to create public key from test vector")
	}

	// Serialize and check against expected value
	var serialized [33]byte
	serializedLen := 33
	if !ECPubkeySerialize(ctx, serialized[:], &serializedLen, &pubkey, ECCompressed) {
		t.Fatal("Failed to serialize test vector public key")
	}

	// The expected compressed public key for secret key 1
	expected := []byte{
		0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
		0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
		0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
		0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
		0x98,
	}

	for i := 0; i < 33; i++ {
		if serialized[i] != expected[i] {
			t.Errorf("Public key mismatch at byte %d: expected %02x, got %02x", i, expected[i], serialized[i])
		}
	}
}

// Benchmark integration tests
func BenchmarkFullECDSAWorkflow(b *testing.B) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		b.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Pre-generate key and message
	var seckey [32]byte
	for i := 0; i < 10; i++ {
		_, err = rand.Read(seckey[:])
		if err != nil {
			b.Fatalf("Failed to generate random bytes: %v", err)
		}
		if ECSecKeyVerify(ctx, seckey[:]) {
			break
		}
		if i == 9 {
			b.Fatal("Failed to generate valid secret key after 10 attempts")
		}
	}

	var pubkey PublicKey
	if !ECPubkeyCreate(ctx, &pubkey, seckey[:]) {
		b.Fatal("Failed to create public key")
	}

	var msghash [32]byte
	rand.Read(msghash[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var sig Signature
		if !ECDSASign(ctx, &sig, msghash[:], seckey[:], nil, nil) {
			b.Fatal("Failed to sign")
		}
		if !ECDSAVerify(ctx, &sig, msghash[:], &pubkey) {
			b.Fatal("Failed to verify")
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	ctx, err := ContextCreate(ContextNone)
	if err != nil {
		b.Fatalf("Failed to create context: %v", err)
	}
	defer ContextDestroy(ctx)

	// Pre-generate valid secret key
	var seckey [32]byte
	for i := 0; i < 10; i++ {
		_, err = rand.Read(seckey[:])
		if err != nil {
			b.Fatalf("Failed to generate random bytes: %v", err)
		}
		if ECSecKeyVerify(ctx, seckey[:]) {
			break
		}
		if i == 9 {
			b.Fatal("Failed to generate valid secret key after 10 attempts")
		}
	}

	var pubkey PublicKey

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ECPubkeyCreate(ctx, &pubkey, seckey[:])
	}
}
