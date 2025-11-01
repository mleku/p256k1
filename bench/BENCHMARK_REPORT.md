# Benchmark Comparison Report

## Signer Implementation Comparison

This report compares three signer implementations for secp256k1 operations:

1. **P256K1Signer** - This repository's new port from Bitcoin Core secp256k1 (pure Go)
2. **BtcecSigner** - Pure Go wrapper around btcec/v2
3. **NextP256K Signer** - CGO version using next.orly.dev/pkg/crypto/p256k (CGO bindings to libsecp256k1)

**Generated:** 2025-11-01 (Updated after optimized windowed multiplication for verification)  
**Platform:** linux/amd64  
**CPU:** AMD Ryzen 5 PRO 4650G with Radeon Graphics  
**Go Version:** go1.25.3

**Key Optimizations:** 
- Implemented 8-bit byte-based precomputed tables matching btcec's approach, resulting in 4x improvement in pubkey derivation and 4.3x improvement in signing.
- Optimized windowed multiplication for verification (5-bit windows, Jacobian coordinate table building): 19% improvement (186,054 → 150,457 ns/op).

---

## Summary Results

| Operation | P256K1Signer | BtcecSigner | NextP256K | Winner |
|-----------|-------------|-------------|-----------|--------|
| **Pubkey Derivation** | 59,056 ns/op | 63,958 ns/op | 269,444 ns/op | P256K1 (8% faster than Btcec) |
| **Sign** | 31,592 ns/op | 219,388 ns/op | 52,233 ns/op | P256K1 (1.7x faster than NextP256K) |
| **Verify** | 150,457 ns/op | 163,867 ns/op | 40,550 ns/op | NextP256K (3.7x faster) |
| **ECDH** | 163,356 ns/op | 136,329 ns/op | 124,423 ns/op | NextP256K (1.3x faster) |

---

## Detailed Results

### Public Key Derivation

Deriving public key from private key (32 bytes → 32 bytes x-only pubkey).

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 59,056 ns/op | 256 B/op | 4 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 63,958 ns/op | 368 B/op | 7 allocs/op | 0.9x slower |
| **NextP256K** | 269,444 ns/op | 983,393 B/op | 9 allocs/op | 0.2x slower |

**Analysis:**
- **P256K1 is fastest** (8% faster than Btcec) after implementing 8-bit byte-based precomputed tables
- Massive improvement: 4x faster than previous implementation (232,922 → 58,618 ns/op)
- NextP256K is slowest, likely due to CGO overhead for small operations
- P256K1 has lowest memory allocation overhead

### Signing (Schnorr)

Creating BIP-340 Schnorr signatures (32-byte message → 64-byte signature).

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 31,592 ns/op | 1,152 B/op | 17 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 219,388 ns/op | 2,193 B/op | 38 allocs/op | 0.1x slower |
| **NextP256K** | 52,233 ns/op | 128 B/op | 3 allocs/op | 0.6x slower |

**Analysis:**
- **P256K1 is fastest** (1.7x faster than NextP256K), benefiting from optimized pubkey derivation
- NextP256K is second fastest, benefiting from optimized C implementation
- Btcec is slowest, likely due to more allocations and pure Go overhead
- NextP256K has lowest memory usage (128 B vs 1,152 B)

### Verification (Schnorr)

Verifying BIP-340 Schnorr signatures (32-byte message + 64-byte signature).

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 150,457 ns/op | 576 B/op | 9 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 163,867 ns/op | 1,120 B/op | 18 allocs/op | 0.9x slower |
| **NextP256K** | 40,550 ns/op | 96 B/op | 2 allocs/op | **3.7x faster** |

**Analysis:**
- NextP256K is dramatically fastest (3.7x faster), showcasing CGO advantage for verification
- **P256K1 is fastest pure Go implementation** (8% faster than Btcec) after optimized windowed multiplication
- **19% improvement** over previous implementation (186,054 → 150,457 ns/op)
- Optimizations: 5-bit windowed multiplication with efficient Jacobian coordinate table building
- NextP256K has minimal memory footprint (96 B vs 576 B)

### ECDH (Shared Secret Generation)

Generating shared secret using Elliptic Curve Diffie-Hellman.

| Implementation | Time per op | Memory | Allocations | Speedup vs P256K1 |
|----------------|-------------|--------|-------------|-------------------|
| **P256K1Signer** | 163,356 ns/op | 241 B/op | 6 allocs/op | 1.0x (baseline) |
| **BtcecSigner** | 136,329 ns/op | 832 B/op | 13 allocs/op | 1.2x faster |
| **NextP256K** | 124,423 ns/op | 160 B/op | 3 allocs/op | **1.3x faster** |

**Analysis:**
- All implementations are relatively close in performance
- NextP256K has slight edge (1.3x faster)
- P256K1 has lowest memory usage (241 B)
- Performance difference is marginal for this operation

---

## Performance Analysis

### Overall Winner: Mixed (P256K1 wins 2/4 operations, NextP256K wins 2/4 operations)

After optimized windowed multiplication for verification:
- **P256K1Signer** wins in 2 out of 4 operations:
  - **Pubkey Derivation:** Fastest (8% faster than Btcec)
  - **Signing:** Fastest (1.7x faster than NextP256K)
- **NextP256K** wins in 2 operations:
  - **Verification:** Fastest (3.7x faster than P256K1, CGO advantage)
  - **ECDH:** Fastest (1.3x faster than P256K1)

### Best Pure Go: P256K1Signer

For pure Go implementations:
- **P256K1** wins for key derivation (8% faster than Btcec)
- **P256K1** wins for signing (6.9x faster than Btcec)
- **P256K1** wins for verification (8% faster than Btcec) - **now fastest pure Go!**
- **Btcec** is faster for ECDH (1.2x faster than P256K1)

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
- **Pubkey derivation or signing performance is critical** (now fastest pure Go)
- Lower memory allocations are preferred
- You want to avoid external C dependencies
- You need the best overall pure Go performance

### Use BtcecSigner when:
- Pure Go is required
- Verification speed is slightly more important than signing/pubkey derivation
- You're already using btcec in your project

---

## Conclusion

The benchmarks demonstrate that:

1. **After optimized windowed multiplication for verification**, P256K1Signer achieves:
   - **Fastest pubkey derivation** among all implementations (59,056 ns/op)
   - **Fastest signing** among all implementations (31,592 ns/op)
   - **Fastest pure Go verification** (150,457 ns/op) - 19% improvement (186,054 → 150,457 ns/op)
   - **8% faster verification than Btcec** in pure Go

2. **Windowed multiplication optimization results:**
   - Implemented 5-bit windowed multiplication with efficient Jacobian coordinate table building
   - Kept all operations in Jacobian coordinates to avoid expensive affine conversions
   - Reduced iterations from 256 (bit-by-bit) to ~52 (5-bit windows)
   - **Successfully improved performance by 19%** over simple binary method

3. **CGO implementations (NextP256K) still provide advantages** for verification (3.7x faster) and ECDH (1.3x faster)

4. **Pure Go implementations are highly competitive**, with P256K1Signer leading in 3 out of 4 operations

5. **Memory efficiency** varies by operation, with P256K1Signer maintaining low memory usage (256 B for pubkey derivation)

The choice between implementations depends on your specific requirements:
- **Maximum performance:** Use NextP256K (CGO) - fastest for verification and ECDH
- **Best pure Go performance:** Use P256K1Signer - fastest for pubkey derivation, signing, and verification (now fastest pure Go for all three!)
- **Pure Go with ECDH focus:** Use BtcecSigner (slightly faster ECDH than P256K1)

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

