//go:build cgo
// +build cgo

package signer

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// BtcecSigner implements the I interface using btcec (pure Go implementation)
type BtcecSigner struct {
	privKey   *btcec.PrivateKey
	pubKey    *btcec.PublicKey
	xonlyPub  []byte // Cached x-only public key
	hasSecret bool
}

// NewBtcecSigner creates a new BtcecSigner instance
func NewBtcecSigner() *BtcecSigner {
	return &BtcecSigner{
		hasSecret: false,
	}
}

// Generate creates a fresh new key pair from system entropy, and ensures it is even (so ECDH works)
func (s *BtcecSigner) Generate() error {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}

	pubKey := privKey.PubKey()
	xonlyPub := schnorr.SerializePubKey(pubKey)

	// Ensure even Y coordinate for ECDH compatibility
	// If the Y coordinate is odd, negate the private key
	pubBytes := pubKey.SerializeCompressed()
	if pubBytes[0] == 0x03 { // Odd Y coordinate
		// Negate the private key
		scalar := privKey.Key
		scalar.Negate()
		privKey = &btcec.PrivateKey{Key: scalar}
		pubKey = privKey.PubKey()
		xonlyPub = schnorr.SerializePubKey(pubKey)
	}

	s.privKey = privKey
	s.pubKey = pubKey
	s.xonlyPub = xonlyPub
	s.hasSecret = true

	return nil
}

// InitSec initialises the secret (signing) key from the raw bytes, and also derives the public key
func (s *BtcecSigner) InitSec(sec []byte) error {
	if len(sec) != 32 {
		return errors.New("secret key must be 32 bytes")
	}

	privKey, pubKey := btcec.PrivKeyFromBytes(sec)
	xonlyPub := schnorr.SerializePubKey(pubKey)

	// Ensure even Y coordinate for ECDH compatibility
	pubBytes := pubKey.SerializeCompressed()
	if pubBytes[0] == 0x03 { // Odd Y coordinate
		// Negate the private key
		scalar := privKey.Key
		scalar.Negate()
		privKey = &btcec.PrivateKey{Key: scalar}
		pubKey = privKey.PubKey()
		xonlyPub = schnorr.SerializePubKey(pubKey)
	}

	s.privKey = privKey
	s.pubKey = pubKey
	s.xonlyPub = xonlyPub
	s.hasSecret = true

	return nil
}

// InitPub initializes the public (verification) key from raw bytes, this is expected to be an x-only 32 byte pubkey
func (s *BtcecSigner) InitPub(pub []byte) error {
	if len(pub) != 32 {
		return errors.New("public key must be 32 bytes")
	}

	pubKey, err := schnorr.ParsePubKey(pub)
	if err != nil {
		return err
	}

	s.pubKey = pubKey
	s.xonlyPub = pub
	s.privKey = nil
	s.hasSecret = false

	return nil
}

// Sec returns the secret key bytes
func (s *BtcecSigner) Sec() []byte {
	if !s.hasSecret || s.privKey == nil {
		return nil
	}
	return s.privKey.Serialize()
}

// Pub returns the public key bytes (x-only schnorr pubkey)
func (s *BtcecSigner) Pub() []byte {
	if s.xonlyPub == nil {
		return nil
	}
	return s.xonlyPub
}

// Sign creates a signature using the stored secret key
func (s *BtcecSigner) Sign(msg []byte) (sig []byte, err error) {
	if !s.hasSecret || s.privKey == nil {
		return nil, errors.New("no secret key available for signing")
	}

	if len(msg) != 32 {
		return nil, errors.New("message must be 32 bytes")
	}

	signature, err := schnorr.Sign(s.privKey, msg)
	if err != nil {
		return nil, err
	}

	return signature.Serialize(), nil
}

// Verify checks a message hash and signature match the stored public key
func (s *BtcecSigner) Verify(msg, sig []byte) (valid bool, err error) {
	if s.pubKey == nil {
		return false, errors.New("no public key available for verification")
	}

	if len(msg) != 32 {
		return false, errors.New("message must be 32 bytes")
	}

	if len(sig) != 64 {
		return false, errors.New("signature must be 64 bytes")
	}

	signature, err := schnorr.ParseSignature(sig)
	if err != nil {
		return false, err
	}

	valid = signature.Verify(msg, s.pubKey)
	return valid, nil
}

// Zero wipes the secret key to prevent memory leaks
func (s *BtcecSigner) Zero() {
	if s.privKey != nil {
		s.privKey.Zero()
		s.privKey = nil
	}
	s.hasSecret = false
	s.pubKey = nil
	s.xonlyPub = nil
}

// ECDH returns a shared secret derived using Elliptic Curve Diffie-Hellman on the I secret and provided pubkey
func (s *BtcecSigner) ECDH(pub []byte) (secret []byte, err error) {
	if !s.hasSecret || s.privKey == nil {
		return nil, errors.New("no secret key available for ECDH")
	}

	if len(pub) != 32 {
		return nil, errors.New("public key must be 32 bytes")
	}

	// Parse x-only pubkey
	pubKey, err := schnorr.ParsePubKey(pub)
	if err != nil {
		return nil, err
	}

	secret = btcec.GenerateSharedSecret(s.privKey, pubKey)
	return secret, nil
}
