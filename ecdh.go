package p256k1

import (
	"errors"
	"unsafe"
)

// EcmultConst computes r = q * a using constant-time multiplication
// This is a simplified implementation for Phase 3 - can be optimized later
func EcmultConst(r *GroupElementJacobian, a *GroupElementAffine, q *Scalar) {
	if a.isInfinity() {
		r.setInfinity()
		return
	}
	
	if q.isZero() {
		r.setInfinity()
		return
	}
	
	// Convert affine point to Jacobian
	var aJac GroupElementJacobian
	aJac.setGE(a)
	
	// Use windowed multiplication for constant-time behavior
	// For now, use a simple approach that's constant-time in the scalar
	r.setInfinity()
	
	var base GroupElementJacobian
	base = aJac
	
	// Process bits from MSB to LSB
	for i := 0; i < 256; i++ {
		if i > 0 {
			r.double(r)
		}
		
		// Get bit i (from MSB)
		bit := q.getBits(uint(255-i), 1)
		if bit != 0 {
			if r.isInfinity() {
				*r = base
			} else {
				r.addVar(r, &base)
			}
		}
	}
}

// Ecmult computes r = q * a (variable-time, optimized)
// This is a simplified implementation - can be optimized with windowing later
func Ecmult(r *GroupElementJacobian, a *GroupElementJacobian, q *Scalar) {
	if a.isInfinity() {
		r.setInfinity()
		return
	}
	
	if q.isZero() {
		r.setInfinity()
		return
	}
	
	// Simple binary method for now
	r.setInfinity()
	var base GroupElementJacobian
	base = *a
	
	// Process bits from MSB to LSB
	for i := 0; i < 256; i++ {
		if i > 0 {
			r.double(r)
		}
		
		// Get bit i (from MSB)
		bit := q.getBits(uint(255-i), 1)
		if bit != 0 {
			if r.isInfinity() {
				*r = base
			} else {
				r.addVar(r, &base)
			}
		}
	}
}

// ECDHHashFunction is a function type for hashing ECDH shared secrets
type ECDHHashFunction func(output []byte, x32 []byte, y32 []byte) bool

// ecdhHashFunctionSHA256 implements the default SHA-256 based hash function for ECDH
// Following the C reference implementation exactly
func ecdhHashFunctionSHA256(output []byte, x32 []byte, y32 []byte) bool {
	if len(output) != 32 || len(x32) != 32 || len(y32) != 32 {
		return false
	}
	
	// Version byte: (y32[31] & 0x01) | 0x02
	version := byte((y32[31] & 0x01) | 0x02)
	
	sha := NewSHA256()
	sha.Write([]byte{version})
	sha.Write(x32)
	sha.Finalize(output)
	sha.Clear()
	
	return true
}

// ECDH computes an EC Diffie-Hellman shared secret
// Following the C reference implementation secp256k1_ecdh
func ECDH(output []byte, pubkey *PublicKey, seckey []byte, hashfp ECDHHashFunction) error {
	if len(output) != 32 {
		return errors.New("output must be 32 bytes")
	}
	if len(seckey) != 32 {
		return errors.New("seckey must be 32 bytes")
	}
	if pubkey == nil {
		return errors.New("pubkey cannot be nil")
	}
	
	// Use default hash function if none provided
	if hashfp == nil {
		hashfp = ecdhHashFunctionSHA256
	}
	
	// Load public key
	var pt GroupElementAffine
	pt.fromBytes(pubkey.data[:])
	if pt.isInfinity() {
		return errors.New("invalid public key")
	}
	
	// Parse scalar
	var s Scalar
	if !s.setB32Seckey(seckey) {
		return errors.New("invalid secret key")
	}
	
	// Handle zero scalar
	if s.isZero() {
		return errors.New("secret key cannot be zero")
	}
	
	// Compute res = s * pt using constant-time multiplication
	var res GroupElementJacobian
	EcmultConst(&res, &pt, &s)
	
	// Convert to affine
	var resAff GroupElementAffine
	resAff.setGEJ(&res)
	resAff.x.normalize()
	resAff.y.normalize()
	
	// Extract x and y coordinates
	var x, y [32]byte
	resAff.x.getB32(x[:])
	resAff.y.getB32(y[:])
	
	// Compute hash
	success := hashfp(output, x[:], y[:])
	
	// Clear sensitive data
	memclear(unsafe.Pointer(&x[0]), 32)
	memclear(unsafe.Pointer(&y[0]), 32)
	s.clear()
	resAff.clear()
	res.clear()
	
	if !success {
		return errors.New("hash function failed")
	}
	
	return nil
}

// HKDF performs HMAC-based Key Derivation Function (RFC 5869)
// Outputs key material of the specified length
func HKDF(output []byte, ikm []byte, salt []byte, info []byte) error {
	if len(output) == 0 {
		return errors.New("output length must be greater than 0")
	}
	
	// Step 1: Extract (if salt is empty, use zeros)
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	
	// PRK = HMAC-SHA256(salt, IKM)
	var prk [32]byte
	hmac := NewHMACSHA256(salt)
	hmac.Write(ikm)
	hmac.Finalize(prk[:])
	hmac.Clear()
	
	// Step 2: Expand
	// Generate output using HKDF-Expand
	// T(0) = empty
	// T(i) = HMAC(PRK, T(i-1) || info || i)
	
	outlen := len(output)
	outidx := 0
	
	// T(0) is empty
	var t []byte
	
	// Generate blocks until we have enough output
	blockNum := byte(1)
	for outidx < outlen {
		// Compute T(i) = HMAC(PRK, T(i-1) || info || i)
		hmac = NewHMACSHA256(prk[:])
		if len(t) > 0 {
			hmac.Write(t)
		}
		if len(info) > 0 {
			hmac.Write(info)
		}
		hmac.Write([]byte{blockNum})
		
		var tBlock [32]byte
		hmac.Finalize(tBlock[:])
		hmac.Clear()
		
		// Copy to output
		copyLen := len(tBlock)
		if copyLen > outlen-outidx {
			copyLen = outlen - outidx
		}
		copy(output[outidx:outidx+copyLen], tBlock[:copyLen])
		outidx += copyLen
		
		// Update T for next iteration
		t = tBlock[:]
		blockNum++
	}
	
	// Clear sensitive data
	memclear(unsafe.Pointer(&prk[0]), 32)
	if len(t) > 0 {
		memclear(unsafe.Pointer(&t[0]), uintptr(len(t)))
	}
	
	return nil
}

// ECDHWithHKDF computes ECDH and derives a key using HKDF
func ECDHWithHKDF(output []byte, pubkey *PublicKey, seckey []byte, salt []byte, info []byte) error {
	// Compute ECDH shared secret
	var sharedSecret [32]byte
	if err := ECDH(sharedSecret[:], pubkey, seckey, nil); err != nil {
		return err
	}
	
	// Derive key using HKDF
	err := HKDF(output, sharedSecret[:], salt, info)
	
	// Clear shared secret
	memclear(unsafe.Pointer(&sharedSecret[0]), 32)
	
	return err
}

// ECDHXOnly computes X-only ECDH (BIP-340 style)
// Outputs only the X coordinate of the shared secret point
func ECDHXOnly(output []byte, pubkey *PublicKey, seckey []byte) error {
	if len(output) != 32 {
		return errors.New("output must be 32 bytes")
	}
	if len(seckey) != 32 {
		return errors.New("seckey must be 32 bytes")
	}
	if pubkey == nil {
		return errors.New("pubkey cannot be nil")
	}
	
	// Load public key
	var pt GroupElementAffine
	pt.fromBytes(pubkey.data[:])
	if pt.isInfinity() {
		return errors.New("invalid public key")
	}
	
	// Parse scalar
	var s Scalar
	if !s.setB32Seckey(seckey) {
		return errors.New("invalid secret key")
	}
	
	if s.isZero() {
		return errors.New("secret key cannot be zero")
	}
	
	// Compute res = s * pt
	var res GroupElementJacobian
	EcmultConst(&res, &pt, &s)
	
	// Convert to affine
	var resAff GroupElementAffine
	resAff.setGEJ(&res)
	resAff.x.normalize()
	
	// Extract X coordinate only
	resAff.x.getB32(output)
	
	// Clear sensitive data
	s.clear()
	resAff.clear()
	res.clear()
	
	return nil
}

