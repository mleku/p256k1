# Benchmark Comparison Report

## Signer Implementation Comparison

This report compares three signer implementations for secp256k1 operations:

1. **P256K1Signer** - This repository's new port from Bitcoin Core secp256k1 (pure Go)
2. **BtcecSigner** - Pure Go wrapper around btcec/v2
3. **NextP256K Signer** - CGO version using next.orly.dev/pkg/crypto/p256k (CGO bindings to libsecp256k1)

**Generated:** 2025-11-02 (Updated after ECDH optimization with windowed multiplication)  
**Platform:** linux/amd64  
**CPU:** AMD Ryzen 5 PRO 4650G with Radeon Graphics  
**Go Version:** go1.25.3

**Key Optimizations:** 
- Implemented 8-bit byte-based precomputed tables matching btcec's approach, resulting in 4x improvement in pubkey derivation and 4.3x improvement in signing.
- Optimized windowed multiplication for verification (5-bit windows, Jacobian coordinate table building): 20% improvement (186,054 → 149,511 ns/op).
- Optimized ECDH with windowed multiplication (5-bit windows): 33% improvement (163,356 → 109,068 ns/op), now fastest for ECDH.

---

## Summary Results

| Operation | P256K1Signer | BtcecSigner | NextP256K | Winner |
|-----------|-------------|-------------|-----------|--------|
| **Pubkey Derivation** | 58,383 ns/op | 62,909 ns/op | 417,383 ns/op | P256K1 (8% faster than Btcec) |
| **Sign** | 63,421 ns/op | 218,085 ns/op | 52,273 ns/op | NextP256K (1.2x faster than P256K1) |
| **Verify** | 149,511 ns/op | 163,396 ns/op | 40,208 ns/op | NextP256K (3.7x faster) |
| **ECDH** | 109,068 ns/op | 127,739 ns/op | 124,039 ns/op | P256K1 (1.1x faster than NextP256K) |

---

## Detailed Results

### Public Key Derivation

Deriving public key from private key (32 bytes → 32 bytes x-only pubkey).

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 58,383 ns/op | 256 B/op | 4 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 62,909 ns/op | 368 B/op | 7 allocs/op | 0.9x slower |
| **NextP256K** | 417,383 ns/op | 983,395 B/op | 9 allocs/op | 0.1x slower |

**Analysis:**
- **P256K1 is fastest** (8% faster than Btcec) after implementing 8-bit byte-based precomputed tables
- Massive improvement: 4x faster than previous implementation (232,922 → 58,618 ns/op)
- NextP256K is slowest, likely due to CGO overhead for small operations
- P256K1 has lowest memory allocation overhead

### Signing (Schnorr)

Creating BIP-340 Schnorr signatures (32-byte message → 64-byte signature).

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 63,421 ns/op | 1,152 B/op | 17 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 218,085 ns/op | 2,193 B/op | 38 allocs/op | 0.3x slower |
| **NextP256K** | 52,273 ns/op | 128 B/op | 3 allocs/op | 1.2x faster |

**Analysis:**
- **NextP256K is fastest** (1.2x faster than P256K1), benefiting from optimized C implementation
- P256K1 is second fastest (3.4x faster than Btcec)
- Btcec is slowest, likely due to more allocations and pure Go overhead
- NextP256K has lowest memory usage (128 B vs 1,152 B)

### Verification (Schnorr)

Verifying BIP-340 Schnorr signatures (32-byte message + 64-byte signature).

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 149,511 ns/op | 576 B/op | 9 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 163,396 ns/op | 1,121 B/op | 18 allocs/op | 0.9x slower |
| **NextP256K** | 40,208 ns/op | 96 B/op | 2 allocs/op | **3.7x faster** |

**Analysis:**
- NextP256K is dramatically fastest (3.7x faster), showcasing CGO advantage for verification
- **P256K1 is fastest pure Go implementation** (8% faster than Btcec) after optimized windowed multiplication
- **20% improvement** over previous implementation (186,054 → 149,511 ns/op)
- Optimizations: 5-bit windowed multiplication with efficient Jacobian coordinate table building
- NextP256K has minimal memory footprint (96 B vs 576 B)

### ECDH (Shared Secret Generation)

Generating shared secret using Elliptic Curve Diffie-Hellman.

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 109,068 ns/op | 241 B/op | 6 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 127,739 ns/op | 832 B/op | 13 allocs/op | 0.9x slower |
| **NextP256K** | 124,039 ns/op | 160 B/op | 3 allocs/op | 0.9x slower |

**Analysis:**
- **P256K1 is fastest** (1.1x faster than NextP256K) after optimizing with windowed multiplication
- **33% improvement** over previous implementation (163,356 → 109,068 ns/op)
- Optimizations: 5-bit windowed multiplication with efficient Jacobian coordinate table building
- P256K1 has lowest memory usage (241 B)

---

## Performance Analysis

### Overall Winner: Mixed (P256K1 wins 2/4 operations, NextP256K wins 2/4 operations)

After optimized windowed multiplication for ECDH:
- **P256K1Signer** wins in 2 out of 4 operations:
  - **Pubkey Derivation:** Fastest (8% faster than Btcec)
  - **ECDH:** Fastest (1.1x faster than NextP256K) - **33% improvement!**
- **NextP256K** wins in 2 operations:
  - **Signing:** Fastest (1.2x faster than P256K1)
  - **Verification:** Fastest (3.7x faster than P256K1, CGO advantage)

### Best Pure Go: P256K1Signer

For pure Go implementations:
- **P256K1** wins for key derivation (8% faster than Btcec)
- **P256K1** wins for signing (3.4x faster than Btcec)
- **P256K1** wins for verification (8% faster than Btcec) - **fastest pure Go!**
- **P256K1** wins for ECDH (1.2x faster than Btcec) - **now fastest pure Go!**

### Memory Efficiency

| Implementation | Avg Memory per Operation | Notes |
|----------------|-------------------------|-------|
| **P256K1Signer** | ~500 B avg | Low memory footprint, consistent across operations |
| **NextP256K** | ~300 KB avg | Very efficient, minimal allocations (except pubkey derivation overhead) |
| **BtcecSigner** | ~1.1 KB avg | Higher allocations, but acceptable |

**Note:** NextP256K shows high memory in pubkey derivation (983 KB) due to one-time CGO initialization overhead, but this is amortized across operations.

---

## Recommendations

### Use NextP256K (CGO) when:
- Maximum performance is critical
- CGO is acceptable in your build environment
- Low memory footprint is important
- Verification speed is critical (4.7x faster)

### Use P256K1Signer when:
- Pure Go is required (no CGO)
- **Pubkey derivation, signing, verification, or ECDH performance is critical** (now fastest pure Go for all operations!)
- Lower memory allocations are preferred
- You want to avoid external C dependencies
- You need the best overall pure Go performance

### Use BtcecSigner when:
- Pure Go is required
- You're already using btcec in your project
- Note: P256K1Signer is faster across all operations

---

## Conclusion

The benchmarks demonstrate that:

1. **After optimized windowed multiplication for ECDH**, P256K1Signer achieves:
   - **Fastest pubkey derivation** among all implementations (58,383 ns/op)
   - **Fastest ECDH** among all implementations (109,068 ns/op) - **33% improvement** (163,356 → 109,068 ns/op)
   - **Fastest pure Go verification** (149,511 ns/op) - 20% improvement (186,054 → 149,511 ns/op)
   - **Fastest pure Go signing** (63,421 ns/op) - 3.4x faster than Btcec

2. **Windowed multiplication optimization results:**
   - Implemented 5-bit windowed multiplication with efficient Jacobian coordinate table building
   - Kept all operations in Jacobian coordinates to avoid expensive affine conversions
   - Reduced iterations from 256 (bit-by-bit) to ~52 (5-bit windows)
   - **ECDH: 33% improvement** (163,356 → 109,068 ns/op)
   - **Verification: 20% improvement** (186,054 → 149,511 ns/op)

3. **CGO implementations (NextP256K) still provide advantages** for verification (3.7x faster) and signing (1.2x faster)

4. **Pure Go implementations are highly competitive**, with P256K1Signer leading in 2 out of 4 operations (pubkey derivation and ECDH)

5. **Memory efficiency** varies by operation, with P256K1Signer maintaining low memory usage (256 B for pubkey derivation, 241 B for ECDH)

The choice between implementations depends on your specific requirements:
- **Maximum performance:** Use NextP256K (CGO) - fastest for verification and signing
- **Best pure Go performance:** Use P256K1Signer - fastest for pubkey derivation and ECDH, fastest pure Go for all operations!
- **Pure Go alternative:** Use BtcecSigner (but P256K1Signer is faster across all operations)

---

## Running the Benchmarks

To reproduce these benchmarks:

```bash
# Run all benchmarks
CGO_ENABLED=1 go test -tags=cgo ./bench -bench=. -benchmem

# Run specific operation
CGO_ENABLED=1 go test -tags=cgo ./bench -bench=BenchmarkSign

# Run specific implementation
CGO_ENABLED=1 go test -tags=cgo ./bench -bench=Benchmark.*_P256K1
```

**Note:** All benchmarks require CGO to be enabled (`CGO_ENABLED=1`) and the `cgo` build tag.

