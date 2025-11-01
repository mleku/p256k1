package p256k1

import (
	"errors"
	"unsafe"
)

// ECDSASignature represents an ECDSA signature
type ECDSASignature struct {
	r, s Scalar
}

// ECDSASign creates an ECDSA signature for a message hash using a private key
func ECDSASign(sig *ECDSASignature, msghash32 []byte, seckey []byte) error {
	if len(msghash32) != 32 {
		return errors.New("message hash must be 32 bytes")
	}
	if len(seckey) != 32 {
		return errors.New("private key must be 32 bytes")
	}
	
	// Parse secret key
	var sec Scalar
	if !sec.setB32Seckey(seckey) {
		return errors.New("invalid private key")
	}
	
	// Parse message hash
	var msg Scalar
	msg.setB32(msghash32)
	
	// Generate nonce using RFC6979
	nonceKey := make([]byte, 64)
	copy(nonceKey[:32], msghash32)
	copy(nonceKey[32:], seckey)
	
	rng := NewRFC6979HMACSHA256(nonceKey)
	memclear(unsafe.Pointer(&nonceKey[0]), 64)
	
	var nonceBytes [32]byte
	rng.Generate(nonceBytes[:])
	
	// Parse nonce
	var nonce Scalar
	if !nonce.setB32Seckey(nonceBytes[:]) {
		// Retry with new nonce
		rng.Generate(nonceBytes[:])
		if !nonce.setB32Seckey(nonceBytes[:]) {
			rng.Finalize()
			rng.Clear()
			return errors.New("nonce generation failed")
		}
	}
	memclear(unsafe.Pointer(&nonceBytes[0]), 32)
	rng.Finalize()
	rng.Clear()
	
	// Compute R = nonce * G
	var rp GroupElementJacobian
	EcmultGen(&rp, &nonce)
	
	// Convert to affine
	var r GroupElementAffine
	r.setGEJ(&rp)
	r.x.normalize()
	r.y.normalize()
	
	// Extract r = X(R) mod n
	var rBytes [32]byte
	r.x.getB32(rBytes[:])
	
	sig.r.setB32(rBytes[:])
	if sig.r.isZero() {
		return errors.New("signature r is zero")
	}
	
	// Compute s = nonce^-1 * (msg + r * sec) mod n
	var n Scalar
	n.mul(&sig.r, &sec)
	n.add(&n, &msg)
	
	var nonceInv Scalar
	nonceInv.inverse(&nonce)
	sig.s.mul(&nonceInv, &n)
	
	// Normalize to low-S
	if sig.s.isHigh() {
		sig.s.condNegate(1)
	}
	
	if sig.s.isZero() {
		return errors.New("signature s is zero")
	}
	
	// Clear sensitive data
	sec.clear()
	msg.clear()
	nonce.clear()
	n.clear()
	nonceInv.clear()
	rp.clear()
	r.clear()
	
	return nil
}

// ECDSAVerify verifies an ECDSA signature against a message hash and public key
func ECDSAVerify(sig *ECDSASignature, msghash32 []byte, pubkey *PublicKey) bool {
	if len(msghash32) != 32 {
		return false
	}
	
	// Check signature components are non-zero
	if sig.r.isZero() || sig.s.isZero() {
		return false
	}
	
	// Parse message hash
	var msg Scalar
	msg.setB32(msghash32)
	
	// Load public key
	var pubkeyPoint GroupElementAffine
	pubkeyPoint.fromBytes(pubkey.data[:])
	if pubkeyPoint.isInfinity() {
		return false
	}
	
	// Compute s^-1 mod n
	var sInv Scalar
	sInv.inverse(&sig.s)
	
	// Compute u1 = msg * s^-1 mod n
	var u1 Scalar
	u1.mul(&msg, &sInv)
	
	// Compute u2 = r * s^-1 mod n
	var u2 Scalar
	u2.mul(&sig.r, &sInv)
	
	// Compute R = u1*G + u2*P
	var u1G, u2P, R GroupElementJacobian
	
	// u1*G
	EcmultGen(&u1G, &u1)
	
	// u2*P
	var pubkeyJac GroupElementJacobian
	pubkeyJac.setGE(&pubkeyPoint)
	
	// For now, use a simple multiplication method
	// TODO: Optimize with proper ecmult implementation
	u2P.setInfinity()
	var base GroupElementJacobian
	base.setGE(&pubkeyPoint)
	
	// Simple binary method for u2*P
	for i := 0; i < 256; i++ {
		if i > 0 {
			u2P.double(&u2P)
		}
		bit := u2.getBits(uint(255-i), 1)
		if bit != 0 {
			if u2P.isInfinity() {
				u2P = base
			} else {
				u2P.addVar(&u2P, &base)
			}
		}
	}
	
	// R = u1*G + u2*P
	R.addVar(&u1G, &u2P)
	
	if R.isInfinity() {
		return false
	}
	
	// Convert R to affine
	var RAff GroupElementAffine
	RAff.setGEJ(&R)
	RAff.x.normalize()
	
	// Extract X(R) mod n
	var rBytes [32]byte
	RAff.x.getB32(rBytes[:])
	
	var computedR Scalar
	computedR.setB32(rBytes[:])
	
	// Compare r with X(R) mod n
	return sig.r.equal(&computedR)
}

// ECDSASignatureCompact represents a compact 64-byte signature (r || s)
type ECDSASignatureCompact [64]byte

// ToCompact converts an ECDSA signature to compact format
func (sig *ECDSASignature) ToCompact() *ECDSASignatureCompact {
	var compact ECDSASignatureCompact
	sig.r.getB32(compact[:32])
	sig.s.getB32(compact[32:])
	return &compact
}

// FromCompact converts a compact signature to ECDSA signature format
func (sig *ECDSASignature) FromCompact(compact *ECDSASignatureCompact) error {
	sig.r.setB32(compact[:32])
	sig.s.setB32(compact[32:64])
	
	if sig.r.isZero() || sig.s.isZero() {
		return errors.New("invalid signature: r or s is zero")
	}
	
	return nil
}

// VerifyCompact verifies a compact signature
func ECDSAVerifyCompact(compact *ECDSASignatureCompact, msghash32 []byte, pubkey *PublicKey) bool {
	var sig ECDSASignature
	if err := sig.FromCompact(compact); err != nil {
		return false
	}
	return ECDSAVerify(&sig, msghash32, pubkey)
}

// SignCompact creates a compact signature
func ECDSASignCompact(compact *ECDSASignatureCompact, msghash32 []byte, seckey []byte) error {
	var sig ECDSASignature
	if err := ECDSASign(&sig, msghash32, seckey); err != nil {
		return err
	}
	*compact = *sig.ToCompact()
	return nil
}

