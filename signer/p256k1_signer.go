package signer

import (
	"errors"

	"p256k1.mleku.dev"
)

// P256K1Signer implements the I and Gen interfaces using the p256k1 package
type P256K1Signer struct {
	keypair   *p256k1.KeyPair
	xonlyPub  *p256k1.XOnlyPubkey
	hasSecret bool // Whether we have the secret key (if false, can only verify)
}

// NewP256K1Signer creates a new P256K1Signer instance
func NewP256K1Signer() *P256K1Signer {
	return &P256K1Signer{
		hasSecret: false,
	}
}

// Generate creates a fresh new key pair from system entropy, and ensures it is even (so ECDH works)
func (s *P256K1Signer) Generate() error {
	kp, err := p256k1.KeyPairGenerate()
	if err != nil {
		return err
	}

	// Ensure even Y coordinate for ECDH compatibility
	// Get x-only pubkey and check parity
	xonly, parity, err := p256k1.XOnlyPubkeyFromPubkey(kp.Pubkey())
	if err != nil {
		return err
	}

	// If parity is 1 (odd Y), negate the secret key
	if parity == 1 {
		seckey := kp.Seckey()
		if !p256k1.ECSeckeyNegate(seckey) {
			return errors.New("failed to negate secret key")
		}
		// Recreate keypair with negated secret key
		kp, err = p256k1.KeyPairCreate(seckey)
		if err != nil {
			return err
		}
		// Get x-only pubkey again (should be even now)
		xonly, _, err = p256k1.XOnlyPubkeyFromPubkey(kp.Pubkey())
		if err != nil {
			return err
		}
	}

	s.keypair = kp
	s.xonlyPub = xonly
	s.hasSecret = true

	return nil
}

// InitSec initialises the secret (signing) key from the raw bytes, and also derives the public key
func (s *P256K1Signer) InitSec(sec []byte) error {
	if len(sec) != 32 {
		return errors.New("secret key must be 32 bytes")
	}

	kp, err := p256k1.KeyPairCreate(sec)
	if err != nil {
		return err
	}

	// Ensure even Y coordinate for ECDH compatibility
	xonly, parity, err := p256k1.XOnlyPubkeyFromPubkey(kp.Pubkey())
	if err != nil {
		return err
	}

	// If parity is 1 (odd Y), negate the secret key and recompute public key
	// With windowed optimization, this is now much faster than before
	if parity == 1 {
		seckey := kp.Seckey()
		if !p256k1.ECSeckeyNegate(seckey) {
			return errors.New("failed to negate secret key")
		}
		// Recreate keypair with negated secret key
		// This is now optimized with windowed precomputed tables
		kp, err = p256k1.KeyPairCreate(seckey)
		if err != nil {
			return err
		}
		xonly, _, err = p256k1.XOnlyPubkeyFromPubkey(kp.Pubkey())
		if err != nil {
			return err
		}
	}

	s.keypair = kp
	s.xonlyPub = xonly
	s.hasSecret = true

	return nil
}

// InitPub initializes the public (verification) key from raw bytes, this is expected to be an x-only 32 byte pubkey
func (s *P256K1Signer) InitPub(pub []byte) error {
	if len(pub) != 32 {
		return errors.New("public key must be 32 bytes")
	}

	xonly, err := p256k1.XOnlyPubkeyParse(pub)
	if err != nil {
		return err
	}

	s.xonlyPub = xonly
	s.keypair = nil
	s.hasSecret = false

	return nil
}

// Sec returns the secret key bytes
func (s *P256K1Signer) Sec() []byte {
	if !s.hasSecret || s.keypair == nil {
		return nil
	}
	return s.keypair.Seckey()
}

// Pub returns the public key bytes (x-only schnorr pubkey)
func (s *P256K1Signer) Pub() []byte {
	if s.xonlyPub == nil {
		return nil
	}
	serialized := s.xonlyPub.Serialize()
	return serialized[:]
}

// Sign creates a signature using the stored secret key
func (s *P256K1Signer) Sign(msg []byte) (sig []byte, err error) {
	if !s.hasSecret || s.keypair == nil {
		return nil, errors.New("no secret key available for signing")
	}

	if len(msg) != 32 {
		return nil, errors.New("message must be 32 bytes")
	}

	var sig64 [64]byte
	if err := p256k1.SchnorrSign(sig64[:], msg, s.keypair, nil); err != nil {
		return nil, err
	}

	return sig64[:], nil
}

// Verify checks a message hash and signature match the stored public key
func (s *P256K1Signer) Verify(msg, sig []byte) (valid bool, err error) {
	if s.xonlyPub == nil {
		return false, errors.New("no public key available for verification")
	}

	if len(msg) != 32 {
		return false, errors.New("message must be 32 bytes")
	}

	if len(sig) != 64 {
		return false, errors.New("signature must be 64 bytes")
	}

	valid = p256k1.SchnorrVerify(sig, msg, s.xonlyPub)
	return valid, nil
}

// Zero wipes the secret key to prevent memory leaks
func (s *P256K1Signer) Zero() {
	if s.keypair != nil {
		s.keypair.Clear()
		s.keypair = nil
	}
	s.hasSecret = false
	// Note: x-only pubkey doesn't contain sensitive data, but we can clear it too
	s.xonlyPub = nil
}

// ECDH returns a shared secret derived using Elliptic Curve Diffie-Hellman on the I secret and provided pubkey
func (s *P256K1Signer) ECDH(pub []byte) (secret []byte, err error) {
	if !s.hasSecret || s.keypair == nil {
		return nil, errors.New("no secret key available for ECDH")
	}

	if len(pub) != 32 {
		return nil, errors.New("public key must be 32 bytes")
	}

	// Convert x-only pubkey (32 bytes) to compressed public key (33 bytes) with even Y
	var compressedPub [33]byte
	compressedPub[0] = 0x02 // Even Y
	copy(compressedPub[1:], pub)

	// Parse the compressed public key
	var pubkey p256k1.PublicKey
	if err := p256k1.ECPubkeyParse(&pubkey, compressedPub[:]); err != nil {
		return nil, err
	}

	// Compute ECDH shared secret using standard ECDH (hashes the point)
	var sharedSecret [32]byte
	if err := p256k1.ECDH(sharedSecret[:], &pubkey, s.keypair.Seckey(), nil); err != nil {
		return nil, err
	}

	return sharedSecret[:], nil
}

// P256K1Gen implements the Gen interface for nostr BIP-340 key generation
type P256K1Gen struct {
	keypair       *p256k1.KeyPair
	xonlyPub      *p256k1.XOnlyPubkey
	compressedPub *p256k1.PublicKey
}

// NewP256K1Gen creates a new P256K1Gen instance
func NewP256K1Gen() *P256K1Gen {
	return &P256K1Gen{}
}

// Generate gathers entropy and derives pubkey bytes for matching, this returns the 33 byte compressed form for checking the oddness of the Y coordinate
func (g *P256K1Gen) Generate() (pubBytes []byte, err error) {
	kp, err := p256k1.KeyPairGenerate()
	if err != nil {
		return nil, err
	}

	g.keypair = kp

	// Get compressed public key (33 bytes)
	var pubkey p256k1.PublicKey = *kp.Pubkey()

	var compressed [33]byte
	n := p256k1.ECPubkeySerialize(compressed[:], &pubkey, p256k1.ECCompressed)
	if n != 33 {
		return nil, errors.New("failed to serialize compressed public key")
	}

	g.compressedPub = &pubkey

	return compressed[:], nil
}

// Negate flips the public key Y coordinate between odd and even
func (g *P256K1Gen) Negate() {
	if g.keypair == nil {
		return
	}

	// Negate the secret key
	seckey := g.keypair.Seckey()
	if !p256k1.ECSeckeyNegate(seckey) {
		return
	}

	// Recreate keypair with negated secret key
	kp, err := p256k1.KeyPairCreate(seckey)
	if err != nil {
		return
	}

	g.keypair = kp

	// Update compressed pubkey
	var pubkey p256k1.PublicKey = *kp.Pubkey()
	var compressed [33]byte
	p256k1.ECPubkeySerialize(compressed[:], &pubkey, p256k1.ECCompressed)
	g.compressedPub = &pubkey

	// Update x-only pubkey
	xonly, err := kp.XOnlyPubkey()
	if err == nil {
		g.xonlyPub = xonly
	}
}

// KeyPairBytes returns the raw bytes of the secret and public key, this returns the 32 byte X-only pubkey
func (g *P256K1Gen) KeyPairBytes() (secBytes, cmprPubBytes []byte) {
	if g.keypair == nil {
		return nil, nil
	}

	secBytes = g.keypair.Seckey()

	if g.xonlyPub == nil {
		xonly, err := g.keypair.XOnlyPubkey()
		if err != nil {
			return secBytes, nil
		}
		g.xonlyPub = xonly
	}

	serialized := g.xonlyPub.Serialize()
	cmprPubBytes = serialized[:]

	return secBytes, cmprPubBytes
}
