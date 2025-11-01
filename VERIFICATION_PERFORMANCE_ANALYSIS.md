# Verification Performance Analysis: NextP256K vs P256K1

## Summary

NextP256K's verification is **4.7x faster** than p256k1 (40,017 ns/op vs 186,054 ns/op) because it uses libsecp256k1's highly optimized C implementation, while p256k1 uses a simple binary multiplication algorithm.

## Root Cause

The performance bottleneck is in `EcmultConst`, which is used to compute `e*P` during Schnorr verification.

### Schnorr Verification Algorithm

```186:289:schnorr.go
// SchnorrVerify verifies a Schnorr signature following BIP-340
func SchnorrVerify(sig64 []byte, msg32 []byte, xonlyPubkey *XOnlyPubkey) bool {
	// ... validation ...
	
	// Compute R = s*G - e*P
	// First compute s*G
	var sG GroupElementJacobian
	EcmultGen(&sG, &s)  // Fast: uses optimized precomputed tables

	// Compute e*P where P is the x-only pubkey
	var eP GroupElementJacobian
	EcmultConst(&eP, &pk, &e)  // Slow: uses simple binary method
	
	// ... rest of verification ...
}
```

### Performance Breakdown

1. **s*G computation** (`EcmultGen`):
   - Uses 8-bit byte-based precomputed tables
   - Highly optimized: ~58,618 ns/op for pubkey derivation
   - Fast because the generator point G is fixed and precomputed

2. **e*P computation** (`EcmultConst`):
   - Uses simple binary method with 256 iterations
   - Each iteration: double, check bit, potentially add
   - **This is the bottleneck**

### Current EcmultConst Implementation

```10:48:ecdh.go
// EcmultConst computes r = q * a using constant-time multiplication
// This is a simplified implementation for Phase 3 - can be optimized later
func EcmultConst(r *GroupElementJacobian, a *GroupElementAffine, q *Scalar) {
	// ... edge cases ...
	
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
```

**Problem:** This performs 256 iterations, each requiring:
- One field element doubling operation
- One bit extraction
- Potentially one point addition

For verification, this means **256 doublings + up to 256 additions** per verification, which is extremely inefficient.

## Why NextP256K is Faster

NextP256K uses libsecp256k1's optimized C implementation (`secp256k1_ecmult_const`) which:

1. **Uses GLV Endomorphism**:
   - Splits the scalar into two smaller components using the curve's endomorphism
   - Computes two smaller multiplications instead of one large one
   - Reduces the effective bit length from 256 to ~128 bits per component

2. **Windowed Precomputation**:
   - Precomputes a table of multiples of the base point
   - Uses windowed lookups instead of processing bits one at a time
   - Processes multiple bits per iteration (typically 4-6 bits at a time)

3. **Signed-Digit Multi-Comb Algorithm**:
   - Uses a more efficient representation that reduces the number of additions
   - Minimizes the number of point operations required

4. **Assembly Optimizations**:
   - Field arithmetic operations are optimized in assembly
   - Hand-tuned for specific CPU architectures

### Reference Implementation

The C reference shows the complexity:

```124:268:src/ecmult_const_impl.h
static void secp256k1_ecmult_const(secp256k1_gej *r, const secp256k1_ge *a, const secp256k1_scalar *q) {
    /* The approach below combines the signed-digit logic from Mike Hamburg's
     * "Fast and compact elliptic-curve cryptography" (https://eprint.iacr.org/2012/309)
     * Section 3.3, with the GLV endomorphism.
     * ... */
    
    /* Precompute table for base point and lambda * base point */
    
    /* Process bits in groups using windowed lookups */
    for (group = ECMULT_CONST_GROUPS - 1; group >= 0; --group) {
        /* Lookup precomputed points */
        ECMULT_CONST_TABLE_GET_GE(&t, pre_a, bits1);
        /* ... */
    }
}
```

## Performance Impact

### Benchmark Results

| Operation | P256K1 | NextP256K | Speedup |
|-----------|--------|-----------|---------|
| **Verification** | 186,054 ns/op | 40,017 ns/op | **4.7x** |
| Signing | 31,937 ns/op | 52,060 ns/op | 0.6x (slower) |
| Pubkey Derivation | 58,618 ns/op | 280,835 ns/op | 0.2x (slower) |

**Note:** NextP256K is slower for signing and pubkey derivation due to CGO overhead for smaller operations, but much faster for verification because the computation is more complex.

## Optimization Opportunities

To improve p256k1's verification performance, `EcmultConst` should be optimized to:

1. **Implement GLV Endomorphism**:
   - Split scalar using secp256k1's endomorphism
   - Compute two smaller multiplications
   - Combine results

2. **Add Windowed Precomputation**:
   - Precompute a table of multiples of the base point
   - Process bits in groups (windows) instead of individually
   - Use lookup tables instead of repeated additions

3. **Consider Variable-Time Optimization**:
   - For verification (public operation), variable-time algorithms are acceptable
   - Could use `Ecmult` instead of `EcmultConst` if constant-time isn't required

4. **Implement Signed-Digit Representation**:
   - Use signed-digit multi-comb algorithm
   - Reduce the number of additions required

## Complexity Comparison

### Current (Simple Binary Method)
- **Operations:** O(256) doublings + O(256) additions (worst case)
- **Complexity:** ~256 point operations

### Optimized (Windowed + GLV)
- **Operations:** O(64) doublings + O(16) additions (with window size 4)
- **Complexity:** ~80 point operations (4x improvement)

### With Assembly Optimizations
- **Additional:** 2-3x speedup from optimized field arithmetic
- **Total:** ~10-15x faster than simple binary method

## Conclusion

The 4.7x performance difference is primarily due to:
1. **Algorithmic efficiency**: Windowed multiplication vs. simple binary method
2. **GLV endomorphism**: Splitting scalar into smaller components
3. **Assembly optimizations**: Hand-tuned field arithmetic in C
4. **Better memory access patterns**: Precomputed tables vs. repeated computations

The optimization is non-trivial and would require implementing:
- GLV endomorphism support
- Windowed precomputation tables
- Signed-digit multi-comb algorithm
- Potentially assembly optimizations for field arithmetic

For now, NextP256K's advantage in verification is expected given its use of the mature, highly optimized libsecp256k1 C library.

