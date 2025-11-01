package p256k1

import (
	"hash"

	"github.com/minio/sha256-simd"
)

// SHA256 represents a SHA-256 hash context
type SHA256 struct {
	hasher hash.Hash
}

// NewSHA256 creates a new SHA-256 hash context
func NewSHA256() *SHA256 {
	return &SHA256{
		hasher: sha256.New(),
	}
}

// Initialize initializes the SHA-256 context
func (h *SHA256) Initialize() {
	h.hasher.Reset()
}

// InitializeTagged initializes the SHA-256 context for tagged hashing (BIP-340)
func (h *SHA256) InitializeTagged(tag []byte) {
	// Compute SHA256(tag)
	tagHash := sha256.Sum256(tag)

	// Initialize with SHA256(tag) || SHA256(tag)
	h.hasher.Reset()
	h.hasher.Write(tagHash[:])
	h.hasher.Write(tagHash[:])
}

// Write adds data to the hash
func (h *SHA256) Write(data []byte) {
	h.hasher.Write(data)
}

// Finalize completes the hash and returns the result
func (h *SHA256) Finalize(output []byte) {
	if len(output) != 32 {
		panic("SHA-256 output must be 32 bytes")
	}

	result := h.hasher.Sum(nil)
	copy(output, result[:])
}

// Clear clears the hash context
func (h *SHA256) Clear() {
	h.hasher.Reset()
}

// TaggedSHA256 computes a tagged hash as defined in BIP-340
func TaggedSHA256(output []byte, tag []byte, msg []byte) {
	if len(output) != 32 {
		panic("output must be 32 bytes")
	}

	// Compute SHA256(tag)
	tagHash := sha256.Sum256(tag)

	// Compute SHA256(SHA256(tag) || SHA256(tag) || msg)
	hasher := sha256.New()
	hasher.Write(tagHash[:])
	hasher.Write(tagHash[:])
	hasher.Write(msg)

	result := hasher.Sum(nil)
	copy(output, result)
}

// SHA256Simple computes a simple SHA-256 hash
func SHA256Simple(output []byte, input []byte) {
	if len(output) != 32 {
		panic("output must be 32 bytes")
	}

	result := sha256.Sum256(input)
	copy(output, result[:])
}

// HMACSHA256 represents an HMAC-SHA256 context for RFC 6979
type HMACSHA256 struct {
	k    [32]byte // HMAC key
	v    [32]byte // HMAC value
	init bool
}

// NewHMACSHA256 creates a new HMAC-SHA256 context
func NewHMACSHA256() *HMACSHA256 {
	return &HMACSHA256{}
}

// Initialize initializes the HMAC context with key data
func (h *HMACSHA256) Initialize(key []byte) {
	// Initialize V = 0x01 0x01 0x01 ... 0x01
	for i := range h.v {
		h.v[i] = 0x01
	}

	// Initialize K = 0x00 0x00 0x00 ... 0x00
	for i := range h.k {
		h.k[i] = 0x00
	}

	// K = HMAC_K(V || 0x00 || key)
	h.updateK(0x00, key)

	// V = HMAC_K(V)
	h.updateV()

	// K = HMAC_K(V || 0x01 || key)
	h.updateK(0x01, key)

	// V = HMAC_K(V)
	h.updateV()

	h.init = true
}

// updateK updates the K value using HMAC
func (h *HMACSHA256) updateK(sep byte, data []byte) {
	// Create HMAC with current K
	mac := NewHMACWithKey(h.k[:])
	mac.Write(h.v[:])
	mac.Write([]byte{sep})
	if data != nil {
		mac.Write(data)
	}
	mac.Finalize(h.k[:])
}

// updateV updates the V value using HMAC
func (h *HMACSHA256) updateV() {
	mac := NewHMACWithKey(h.k[:])
	mac.Write(h.v[:])
	mac.Finalize(h.v[:])
}

// Generate generates pseudorandom bytes
func (h *HMACSHA256) Generate(output []byte) {
	if !h.init {
		panic("HMAC not initialized")
	}

	outputLen := len(output)
	generated := 0

	for generated < outputLen {
		// V = HMAC_K(V)
		h.updateV()

		// Copy V to output
		toCopy := 32
		if generated+toCopy > outputLen {
			toCopy = outputLen - generated
		}
		copy(output[generated:generated+toCopy], h.v[:toCopy])
		generated += toCopy
	}
}

// Finalize finalizes the HMAC context
func (h *HMACSHA256) Finalize() {
	// Clear sensitive data
	for i := range h.k {
		h.k[i] = 0
	}
	for i := range h.v {
		h.v[i] = 0
	}
	h.init = false
}

// Clear clears the HMAC context
func (h *HMACSHA256) Clear() {
	h.Finalize()
}

// HMAC represents an HMAC context
type HMAC struct {
	inner  *SHA256
	outer  *SHA256
	keyLen int
}

// NewHMACWithKey creates a new HMAC context with the given key
func NewHMACWithKey(key []byte) *HMAC {
	h := &HMAC{
		inner:  NewSHA256(),
		outer:  NewSHA256(),
		keyLen: len(key),
	}

	// Prepare key
	var k [64]byte
	if len(key) > 64 {
		// Hash long keys
		hasher := sha256.New()
		hasher.Write(key)
		result := hasher.Sum(nil)
		copy(k[:], result)
	} else {
		copy(k[:], key)
	}

	// Create inner and outer keys
	var ikey, okey [64]byte
	for i := 0; i < 64; i++ {
		ikey[i] = k[i] ^ 0x36
		okey[i] = k[i] ^ 0x5c
	}

	// Initialize inner hash with inner key
	h.inner.Initialize()
	h.inner.Write(ikey[:])

	// Initialize outer hash with outer key
	h.outer.Initialize()
	h.outer.Write(okey[:])

	return h
}

// Write adds data to the HMAC
func (h *HMAC) Write(data []byte) {
	h.inner.Write(data)
}

// Finalize completes the HMAC and returns the result
func (h *HMAC) Finalize(output []byte) {
	if len(output) != 32 {
		panic("HMAC output must be 32 bytes")
	}

	// Get inner hash result
	var innerResult [32]byte
	h.inner.Finalize(innerResult[:])

	// Complete outer hash
	h.outer.Write(innerResult[:])
	h.outer.Finalize(output)
}

// RFC6979HMACSHA256 implements RFC 6979 deterministic nonce generation
type RFC6979HMACSHA256 struct {
	hmac *HMACSHA256
}

// NewRFC6979HMACSHA256 creates a new RFC 6979 HMAC context
func NewRFC6979HMACSHA256() *RFC6979HMACSHA256 {
	return &RFC6979HMACSHA256{
		hmac: NewHMACSHA256(),
	}
}

// Initialize initializes the RFC 6979 context
func (r *RFC6979HMACSHA256) Initialize(key []byte) {
	r.hmac.Initialize(key)
}

// Generate generates deterministic nonce bytes
func (r *RFC6979HMACSHA256) Generate(output []byte) {
	r.hmac.Generate(output)
}

// Finalize finalizes the RFC 6979 context
func (r *RFC6979HMACSHA256) Finalize() {
	r.hmac.Finalize()
}

// Clear clears the RFC 6979 context
func (r *RFC6979HMACSHA256) Clear() {
	r.hmac.Clear()
}
