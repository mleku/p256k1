package p256k1

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSHA256Simple(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:  "empty",
			input: []byte{},
			expected: []byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
			},
		},
		{
			name:  "abc",
			input: []byte("abc"),
			expected: []byte{
				0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
				0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
				0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
				0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
			},
		},
		{
			name:  "long_message",
			input: []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			expected: []byte{
				0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
				0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
				0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
				0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var output [32]byte
			SHA256Simple(output[:], tc.input)

			if !bytes.Equal(output[:], tc.expected) {
				t.Errorf("SHA256 mismatch.\nExpected: %x\nGot:      %x", tc.expected, output[:])
			}

			// Compare with Go's crypto/sha256
			goHash := sha256.Sum256(tc.input)
			if !bytes.Equal(output[:], goHash[:]) {
				t.Errorf("SHA256 doesn't match Go's implementation.\nExpected: %x\nGot:      %x", goHash[:], output[:])
			}
		})
	}
}

func TestTaggedSHA256(t *testing.T) {
	testCases := []struct {
		name string
		tag  []byte
		msg  []byte
	}{
		{
			name: "BIP340_challenge",
			tag:  []byte("BIP0340/challenge"),
			msg:  []byte("test message"),
		},
		{
			name: "BIP340_nonce",
			tag:  []byte("BIP0340/nonce"),
			msg:  []byte("another test"),
		},
		{
			name: "custom_tag",
			tag:  []byte("custom/tag"),
			msg:  []byte("custom message"),
		},
		{
			name: "empty_message",
			tag:  []byte("test/tag"),
			msg:  []byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var output [32]byte
			TaggedSHA256(output[:], tc.tag, tc.msg)

			// Verify output is not all zeros
			allZero := true
			for _, b := range output {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("Tagged SHA256 output should not be all zeros")
			}

			// Test determinism - same inputs should produce same output
			var output2 [32]byte
			TaggedSHA256(output2[:], tc.tag, tc.msg)

			if !bytes.Equal(output[:], output2[:]) {
				t.Error("Tagged SHA256 should be deterministic")
			}

			// Test that different tags produce different outputs (for same message)
			if len(tc.tag) > 0 {
				differentTag := make([]byte, len(tc.tag))
				copy(differentTag, tc.tag)
				differentTag[0] ^= 1 // Flip one bit

				var outputDifferentTag [32]byte
				TaggedSHA256(outputDifferentTag[:], differentTag, tc.msg)

				if bytes.Equal(output[:], outputDifferentTag[:]) {
					t.Error("Different tags should produce different outputs")
				}
			}
		})
	}
}

func TestTaggedSHA256Specification(t *testing.T) {
	// Test that tagged SHA256 follows BIP-340 specification:
	// tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)

	tag := []byte("BIP0340/challenge")
	msg := []byte("test message")

	var ourOutput [32]byte
	TaggedSHA256(ourOutput[:], tag, msg)

	// Compute expected result according to specification
	tagHash := sha256.Sum256(tag)
	
	var combined []byte
	combined = append(combined, tagHash[:]...)
	combined = append(combined, tagHash[:]...)
	combined = append(combined, msg...)
	
	expectedOutput := sha256.Sum256(combined)

	if !bytes.Equal(ourOutput[:], expectedOutput[:]) {
		t.Errorf("Tagged SHA256 doesn't match specification.\nExpected: %x\nGot:      %x", expectedOutput[:], ourOutput[:])
	}
}

func TestHMACDRBG(t *testing.T) {
	// Test HMAC-DRBG functionality - simplified test
	seed := []byte("test seed for HMAC-DRBG")
	
	// Test that we can create and use RFC6979 nonce function
	var msg32, key32, nonce32 [32]byte
	copy(key32[:], seed)
	copy(msg32[:], []byte("test message"))
	
	success := rfc6979NonceFunction(nonce32[:], msg32[:], key32[:], nil, nil, 0)
	if !success {
		t.Error("RFC 6979 nonce generation should succeed")
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
}

func TestRFC6979NonceFunction(t *testing.T) {
	// Test the RFC 6979 nonce function used in ECDSA signing
	var msg32, key32, nonce32 [32]byte
	
	// Fill with test data
	for i := range msg32 {
		msg32[i] = byte(i)
		key32[i] = byte(i + 1)
	}

	// Generate nonce
	success := rfc6979NonceFunction(nonce32[:], msg32[:], key32[:], nil, nil, 0)
	if !success {
		t.Error("RFC 6979 nonce generation should succeed")
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
		t.Error("Second RFC 6979 nonce generation should succeed")
	}

	if !bytes.Equal(nonce32[:], nonce32_2[:]) {
		t.Error("RFC 6979 nonce generation should be deterministic")
	}

	// Test different attempt numbers produce different nonces
	var nonce32_attempt1 [32]byte
	success = rfc6979NonceFunction(nonce32_attempt1[:], msg32[:], key32[:], nil, nil, 1)
	if !success {
		t.Error("RFC 6979 nonce generation with attempt=1 should succeed")
	}

	if bytes.Equal(nonce32[:], nonce32_attempt1[:]) {
		t.Error("Different attempt numbers should produce different nonces")
	}
}

func TestRFC6979WithExtraData(t *testing.T) {
	// Test RFC 6979 with extra entropy
	var msg32, key32, nonce32_no_extra, nonce32_with_extra [32]byte
	
	for i := range msg32 {
		msg32[i] = byte(i)
		key32[i] = byte(i + 1)
	}

	extraData := []byte("extra entropy for testing")

	// Generate nonce without extra data
	success := rfc6979NonceFunction(nonce32_no_extra[:], msg32[:], key32[:], nil, nil, 0)
	if !success {
		t.Error("RFC 6979 nonce generation without extra data should succeed")
	}

	// Generate nonce with extra data
	success = rfc6979NonceFunction(nonce32_with_extra[:], msg32[:], key32[:], nil, extraData, 0)
	if !success {
		t.Error("RFC 6979 nonce generation with extra data should succeed")
	}

	// Results should be different
	if bytes.Equal(nonce32_no_extra[:], nonce32_with_extra[:]) {
		t.Error("Extra data should change the nonce")
	}
}

func TestHashEdgeCases(t *testing.T) {
	// Test with very large inputs
	largeInput := make([]byte, 1000000) // 1MB
	for i := range largeInput {
		largeInput[i] = byte(i % 256)
	}

	var output [32]byte
	SHA256Simple(output[:], largeInput)

	// Should not be all zeros
	allZero := true
	for _, b := range output {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("SHA256 of large input should not be all zeros")
	}

	// Test tagged SHA256 with large tag and message
	largeTag := make([]byte, 1000)
	for i := range largeTag {
		largeTag[i] = byte(i % 256)
	}

	TaggedSHA256(output[:], largeTag, largeInput[:1000]) // Use first 1000 bytes

	// Should not be all zeros
	allZero = true
	for _, b := range output {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Tagged SHA256 of large inputs should not be all zeros")
	}
}

// Benchmark tests
func BenchmarkSHA256Simple(b *testing.B) {
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

func BenchmarkHMACDRBGGenerate(b *testing.B) {
	// Benchmark RFC6979 nonce generation instead
	var msg32, key32, nonce32 [32]byte
	
	for i := range msg32 {
		msg32[i] = byte(i)
		key32[i] = byte(i + 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rfc6979NonceFunction(nonce32[:], msg32[:], key32[:], nil, nil, 0)
	}
}

func BenchmarkRFC6979NonceFunction(b *testing.B) {
	var msg32, key32, nonce32 [32]byte
	
	for i := range msg32 {
		msg32[i] = byte(i)
		key32[i] = byte(i + 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rfc6979NonceFunction(nonce32[:], msg32[:], key32[:], nil, nil, 0)
	}
}
