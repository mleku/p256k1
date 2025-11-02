# Verify Function Performance Analysis: C vs Go

## Key Finding: The C Version Uses Strauss-WNAF Algorithm

The C implementation of `secp256k1_schnorrsig_verify` uses a **highly optimized Strauss-WNAF algorithm** that computes `r = s*G + (-e)*P` in a **single interleaved operation** rather than two separate multiplications.

## Current Go Implementation (verify.go:692-722)

```go
func secp256k1_ecmult(r *secp256k1_gej, a *secp256k1_gej, na *secp256k1_scalar, ng *secp256k1_scalar) {
    // r = na * a + ng * G
    // First compute na * a
    var naa GroupElementJacobian
    Ecmult(&naa, &geja, &sna)  // ~43 iterations (6-bit windows)
    
    // Then compute ng * G
    var ngg GroupElementJacobian
    EcmultGen(&ngg, &sng)  // ~32 iterations (byte-based)
    
    // Add them together
    gejr.addVar(&naa, &ngg)
}
```

**Performance**: ~75 iterations total (43 + 32), plus one addition

## C Implementation (src/ecmult_impl.h:321-342)

```c
for (i = bits - 1; i >= 0; i--) {
    secp256k1_gej_double_var(r, r, NULL);  // ONE doubling per iteration
    // Check na*a contribution
    if (i < bits_na_1 && (n = wnaf_na_1[i])) {
        secp256k1_ecmult_table_get_ge(&tmpa, pre_a, n, WINDOW_A);
        secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
    }
    // Check ng*G contribution  
    if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
        secp256k1_ecmult_table_get_ge_storage(&tmpa, secp256k1_pre_g, n, WINDOW_G);
        secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
    }
}
```

**Performance**: ~129 iterations total (max bits needed), with interleaved additions

## Why C is Faster

### 1. **Interleaved Operations**
- **C**: Processes both scalars bit-by-bit in ONE loop
  - Each iteration: double once, then potentially add from either table
  - Total: ~129 iterations (the maximum bits needed)
  
- **Go**: Computes two separate multiplications
  - `na*a`: ~43 iterations (6-bit windows)
  - `ng*G`: ~32 iterations (byte-based)
  - Total: ~75 iterations PLUS one final addition

### 2. **GLV Endomorphism Optimization**
The C version uses scalar splitting with lambda endomorphism:
- Splits `na` into `na_1` and `na_lam` (~128 bits each)
- Uses precomputed lambda table for faster operations
- Reduces effective scalar size from 256 bits to ~128 bits

### 3. **WNAF (Windowed Non-Adjacent Form)**
- Sparse representation: non-zero entries separated by at least (w-1) zeroes
- Reduces number of additions needed
- Uses signed digits: can subtract instead of just add

### 4. **Precomputed Tables**
- C uses optimized precomputed tables for both `a` and `G`
- Uses isomorphic curve representation for faster affine additions
- Stores points in optimized storage format

### 5. **Fewer Doublings**
- **C**: ~129 doublings (one per bit position)
- **Go**: ~43 doublings for `na*a` + ~32 doublings for `ng*G` = ~75 doublings
- But C also does fewer additions due to WNAF sparsity

## Performance Impact

The C version is ~3-4x faster because:
1. **Single loop**: Processes everything in one pass (~129 iterations vs ~75+1)
2. **Sparse operations**: WNAF reduces additions (maybe 20-30 additions vs 32+)
3. **Optimized tables**: Precomputed tables with isomorphic curve optimization
4. **Better cache locality**: Everything in one loop, better CPU cache usage

## Recommendation

To match C performance, implement the Strauss-WNAF algorithm in Go:
1. Implement WNAF conversion for scalars
2. Implement GLV endomorphism scalar splitting
3. Implement interleaved multiplication loop
4. Use precomputed tables with isomorphic curve optimization
5. This will require implementing several missing functions:
   - `secp256k1_scalar_split_lambda`
   - `secp256k1_scalar_split_128`
   - `secp256k1_ecmult_wnaf`
   - `secp256k1_ecmult_odd_multiples_table`
   - `secp256k1_ge_table_set_globalz`
   - `secp256k1_ecmult_table_get_ge`
   - `secp256k1_ecmult_table_get_ge_lambda`
   - `secp256k1_ecmult_table_get_ge_storage`
   - And the GLV lambda constant/endomorphism functions

This is a significant optimization that would bring Go performance much closer to C.

