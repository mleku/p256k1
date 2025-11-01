//go:build cgo
// +build cgo

package bench

import (
	"crypto/rand"
	"testing"

	p256knext "next.orly.dev/pkg/crypto/p256k"
	"p256k1.mleku.dev/signer"
)

// This file contains benchmarks comparing the three signer implementations:
// 1. P256K1Signer (this package's new port from Bitcoin Core secp256k1)
// 2. BtcecSigner (pure Go btcec wrapper)
// 3. NextP256K Signer (CGO version using next.orly.dev/pkg/crypto/p256k)

var (
	benchSeckey   []byte
	benchMsghash  []byte
	compBenchSignerP256K1  *signer.P256K1Signer
	compBenchSignerBtcec   *signer.BtcecSigner
	compBenchSignerNext    *p256knext.Signer
	compBenchSignerP256K12 *signer.P256K1Signer
	compBenchSignerBtcec2  *signer.BtcecSigner
	compBenchSignerNext2   *p256knext.Signer
	compBenchSigP256K1     []byte
	compBenchSigBtcec      []byte
	compBenchSigNext       []byte
)

func initComparisonBenchData() {
	// Generate a fixed secret key for benchmarks
	if benchSeckey == nil {
		benchSeckey = []byte{
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		}

		// Ensure it's valid (non-zero and less than order)
		// We'll validate by trying to create a signer
		for {
			testSigner := signer.NewP256K1Signer()
			if err := testSigner.InitSec(benchSeckey); err == nil {
				break
			}
			if _, err := rand.Read(benchSeckey); err != nil {
				panic(err)
			}
		}

		// Create message hash
		benchMsghash = make([]byte, 32)
		if _, err := rand.Read(benchMsghash); err != nil {
			panic(err)
		}
	}

	// Setup P256K1Signer (this repo's implementation)
	signer1 := signer.NewP256K1Signer()
	if err := signer1.InitSec(benchSeckey); err != nil {
		panic(err)
	}
	compBenchSignerP256K1 = signer1

	var err error
	compBenchSigP256K1, err = signer1.Sign(benchMsghash)
	if err != nil {
		panic(err)
	}

	// Setup BtcecSigner (pure Go)
	signer2 := signer.NewBtcecSigner()
	if err := signer2.InitSec(benchSeckey); err != nil {
		panic(err)
	}
	compBenchSignerBtcec = signer2

	compBenchSigBtcec, err = signer2.Sign(benchMsghash)
	if err != nil {
		panic(err)
	}

	// Setup NextP256K Signer (CGO version)
	signer3 := &p256knext.Signer{}
	if err := signer3.InitSec(benchSeckey); err != nil {
		panic(err)
	}
	compBenchSignerNext = signer3

	compBenchSigNext, err = signer3.Sign(benchMsghash)
	if err != nil {
		panic(err)
	}

	// Generate second key pair for ECDH
	seckey2 := make([]byte, 32)
	for {
		if _, err := rand.Read(seckey2); err != nil {
			panic(err)
		}
		// Validate by trying to create a signer
		testSigner := signer.NewP256K1Signer()
		if err := testSigner.InitSec(seckey2); err == nil {
			break
		}
	}

	// P256K1Signer second key pair
	signer12 := signer.NewP256K1Signer()
	if err := signer12.InitSec(seckey2); err != nil {
		panic(err)
	}
	compBenchSignerP256K12 = signer12

	// BtcecSigner second key pair
	signer22 := signer.NewBtcecSigner()
	if err := signer22.InitSec(seckey2); err != nil {
		panic(err)
	}
	compBenchSignerBtcec2 = signer22

	// NextP256K Signer second key pair
	signer32 := &p256knext.Signer{}
	if err := signer32.InitSec(seckey2); err != nil {
		panic(err)
	}
	compBenchSignerNext2 = signer32
}

// BenchmarkPubkeyDerivation compares public key derivation from private key
func BenchmarkPubkeyDerivation_P256K1(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := signer.NewP256K1Signer()
		if err := s.InitSec(benchSeckey); err != nil {
			b.Fatalf("failed to create signer: %v", err)
		}
		_ = s.Pub()
	}
}

func BenchmarkPubkeyDerivation_Btcec(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := signer.NewBtcecSigner()
		if err := s.InitSec(benchSeckey); err != nil {
			b.Fatalf("failed to create signer: %v", err)
		}
		_ = s.Pub()
	}
}

func BenchmarkPubkeyDerivation_NextP256K(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := &p256knext.Signer{}
		if err := s.InitSec(benchSeckey); err != nil {
			b.Fatalf("failed to create signer: %v", err)
		}
		_ = s.Pub()
	}
}

// BenchmarkSign compares Schnorr signing
func BenchmarkSign_P256K1(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if compBenchSignerP256K1 == nil {
			initComparisonBenchData()
		}
		_, err := compBenchSignerP256K1.Sign(benchMsghash)
		if err != nil {
			b.Fatalf("failed to sign: %v", err)
		}
	}
}

func BenchmarkSign_Btcec(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if compBenchSignerBtcec == nil {
			initComparisonBenchData()
		}
		_, err := compBenchSignerBtcec.Sign(benchMsghash)
		if err != nil {
			b.Fatalf("failed to sign: %v", err)
		}
	}
}

func BenchmarkSign_NextP256K(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if compBenchSignerNext == nil {
			initComparisonBenchData()
		}
		_, err := compBenchSignerNext.Sign(benchMsghash)
		if err != nil {
			b.Fatalf("failed to sign: %v", err)
		}
	}
}

// BenchmarkVerify compares Schnorr verification
func BenchmarkVerify_P256K1(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	if compBenchSignerP256K1 == nil || compBenchSigP256K1 == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier := signer.NewP256K1Signer()
		if err := verifier.InitPub(compBenchSignerP256K1.Pub()); err != nil {
			b.Fatalf("failed to create verifier: %v", err)
		}
		valid, err := verifier.Verify(benchMsghash, compBenchSigP256K1)
		if err != nil {
			b.Fatalf("verification error: %v", err)
		}
		if !valid {
			b.Fatalf("verification failed")
		}
	}
}

func BenchmarkVerify_Btcec(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	if compBenchSignerBtcec == nil || compBenchSigBtcec == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier := signer.NewBtcecSigner()
		if err := verifier.InitPub(compBenchSignerBtcec.Pub()); err != nil {
			b.Fatalf("failed to create verifier: %v", err)
		}
		valid, err := verifier.Verify(benchMsghash, compBenchSigBtcec)
		if err != nil {
			b.Fatalf("verification error: %v", err)
		}
		if !valid {
			b.Fatalf("verification failed")
		}
	}
}

func BenchmarkVerify_NextP256K(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	if compBenchSignerNext == nil || compBenchSigNext == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier := &p256knext.Signer{}
		if err := verifier.InitPub(compBenchSignerNext.Pub()); err != nil {
			b.Fatalf("failed to create verifier: %v", err)
		}
		valid, err := verifier.Verify(benchMsghash, compBenchSigNext)
		if err != nil {
			b.Fatalf("verification error: %v", err)
		}
		if !valid {
			b.Fatalf("verification failed")
		}
	}
}

// BenchmarkECDH compares ECDH shared secret generation
func BenchmarkECDH_P256K1(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if compBenchSignerP256K1 == nil || compBenchSignerP256K12 == nil {
			initComparisonBenchData()
		}
		_, err := compBenchSignerP256K1.ECDH(compBenchSignerP256K12.Pub())
		if err != nil {
			b.Fatalf("ECDH failed: %v", err)
		}
	}
}

func BenchmarkECDH_Btcec(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if compBenchSignerBtcec == nil || compBenchSignerBtcec2 == nil {
			initComparisonBenchData()
		}
		_, err := compBenchSignerBtcec.ECDH(compBenchSignerBtcec2.Pub())
		if err != nil {
			b.Fatalf("ECDH failed: %v", err)
		}
	}
}

func BenchmarkECDH_NextP256K(b *testing.B) {
	if benchSeckey == nil {
		initComparisonBenchData()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if compBenchSignerNext == nil || compBenchSignerNext2 == nil {
			initComparisonBenchData()
		}
		_, err := compBenchSignerNext.ECDH(compBenchSignerNext2.Pub())
		if err != nil {
			b.Fatalf("ECDH failed: %v", err)
		}
	}
}

