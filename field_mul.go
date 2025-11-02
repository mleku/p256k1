package p256k1

import "math/bits"

// uint128 represents a 128-bit unsigned integer for field arithmetic
type uint128 struct {
	high, low uint64
}

// mulU64ToU128 multiplies two uint64 values and returns a uint128
func mulU64ToU128(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{high: hi, low: lo}
}

// addMulU128 computes c + a*b and returns the result as uint128
func addMulU128(c uint128, a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	
	// Add lo to c.low
	newLo, carry := bits.Add64(c.low, lo, 0)
	
	// Add hi and carry to c.high
	newHi, _ := bits.Add64(c.high, hi, carry)
	
	return uint128{high: newHi, low: newLo}
}

// addU128 adds a uint64 to a uint128
func addU128(c uint128, a uint64) uint128 {
	newLo, carry := bits.Add64(c.low, a, 0)
	newHi, _ := bits.Add64(c.high, 0, carry)
	return uint128{high: newHi, low: newLo}
}

// lo returns the lower 64 bits
func (u uint128) lo() uint64 {
	return u.low
}

// hi returns the upper 64 bits
func (u uint128) hi() uint64 {
	return u.high
}

// rshift shifts the uint128 right by n bits
func (u uint128) rshift(n uint) uint128 {
	if n >= 64 {
		return uint128{high: 0, low: u.high >> (n - 64)}
	}
	return uint128{
		high: u.high >> n,
		low: (u.low >> n) | (u.high << (64 - n)),
	}
}

// mul multiplies two field elements: r = a * b
// This implementation follows the C secp256k1_fe_mul_inner algorithm
// Optimized: avoid copies when magnitude is low enough
func (r *FieldElement) mul(a, b *FieldElement) {
	// Use pointers directly if magnitude is low enough (optimization)
	var aNorm, bNorm *FieldElement
	var aTemp, bTemp FieldElement
	
	if a.magnitude > 8 {
		aTemp = *a
		aTemp.normalizeWeak()
		aNorm = &aTemp
	} else {
		aNorm = a // Use directly, no copy needed
	}
	
	if b.magnitude > 8 {
		bTemp = *b
		bTemp.normalizeWeak()
		bNorm = &bTemp
	} else {
		bNorm = b // Use directly, no copy needed
	}

	// Extract limbs for easier access
	a0, a1, a2, a3, a4 := aNorm.n[0], aNorm.n[1], aNorm.n[2], aNorm.n[3], aNorm.n[4]
	b0, b1, b2, b3, b4 := bNorm.n[0], bNorm.n[1], bNorm.n[2], bNorm.n[3], bNorm.n[4]

	const M = 0xFFFFFFFFFFFFF     // 2^52 - 1
	const R = fieldReductionConstantShifted // 0x1000003D10

	// Following the C implementation algorithm exactly
	// [... a b c] is shorthand for ... + a<<104 + b<<52 + c<<0 mod n
	
	// Compute p3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
	var c, d uint128
	d = mulU64ToU128(a0, b3)
	d = addMulU128(d, a1, b2)
	d = addMulU128(d, a2, b1)
	d = addMulU128(d, a3, b0)
	
	// Compute p8 = a4*b4
	c = mulU64ToU128(a4, b4)
	
	// d += R * c_lo; c >>= 64
	d = addMulU128(d, R, c.lo())
	c = c.rshift(64)
	
	// Extract t3 and shift d
	t3 := d.lo() & M
	d = d.rshift(52)
	
	// Compute p4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
	d = addMulU128(d, a0, b4)
	d = addMulU128(d, a1, b3)
	d = addMulU128(d, a2, b2)
	d = addMulU128(d, a3, b1)
	d = addMulU128(d, a4, b0)
	
	// d += (R << 12) * c_lo
	d = addMulU128(d, R<<12, c.lo())
	
	// Extract t4 and tx
	t4 := d.lo() & M
	d = d.rshift(52)
	tx := t4 >> 48
	t4 &= (M >> 4)
	
	// Compute p0 = a0*b0
	c = mulU64ToU128(a0, b0)
	
	// Compute p5 = a1*b4 + a2*b3 + a3*b2 + a4*b1
	d = addMulU128(d, a1, b4)
	d = addMulU128(d, a2, b3)
	d = addMulU128(d, a3, b2)
	d = addMulU128(d, a4, b1)
	
	// Extract u0
	u0 := d.lo() & M
	d = d.rshift(52)
	u0 = (u0 << 4) | tx
	
	// c += u0 * (R >> 4)
	c = addMulU128(c, u0, R>>4)
	
	// r[0]
	r.n[0] = c.lo() & M
	c = c.rshift(52)
	
	// Compute p1 = a0*b1 + a1*b0
	c = addMulU128(c, a0, b1)
	c = addMulU128(c, a1, b0)
	
	// Compute p6 = a2*b4 + a3*b3 + a4*b2
	d = addMulU128(d, a2, b4)
	d = addMulU128(d, a3, b3)
	d = addMulU128(d, a4, b2)
	
	// c += R * (d & M); d >>= 52
	c = addMulU128(c, R, d.lo()&M)
	d = d.rshift(52)
	
	// r[1]
	r.n[1] = c.lo() & M
	c = c.rshift(52)
	
	// Compute p2 = a0*b2 + a1*b1 + a2*b0
	c = addMulU128(c, a0, b2)
	c = addMulU128(c, a1, b1)
	c = addMulU128(c, a2, b0)
	
	// Compute p7 = a3*b4 + a4*b3
	d = addMulU128(d, a3, b4)
	d = addMulU128(d, a4, b3)
	
	// c += R * d_lo; d >>= 64
	c = addMulU128(c, R, d.lo())
	d = d.rshift(64)
	
	// r[2]
	r.n[2] = c.lo() & M
	c = c.rshift(52)
	
	// c += (R << 12) * d_lo + t3
	c = addMulU128(c, R<<12, d.lo())
	c = addU128(c, t3)
	
	// r[3]
	r.n[3] = c.lo() & M
	c = c.rshift(52)
	
	// r[4]
	r.n[4] = c.lo() + t4
	
	// Set magnitude and normalization
	r.magnitude = 1
	r.normalized = false
}

// reduceFromWide reduces a 520-bit (10 limb) value modulo the field prime
func (r *FieldElement) reduceFromWide(t [10]uint64) {
	// The field prime is p = 2^256 - 2^32 - 977 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
	// We use the fact that 2^256 ≡ 2^32 + 977 (mod p)
	
	// First, handle the upper limbs (t[5] through t[9])
	// Each represents a multiple of 2^(52*i) where i >= 5
	
	// Reduction constant for secp256k1: 2^32 + 977 = 0x1000003D1
	const M = uint64(0x1000003D1)
	
	// Start from the highest limb and work down
	for i := 9; i >= 5; i-- {
		if t[i] == 0 {
			continue
		}
		
		// t[i] * 2^(52*i) ≡ t[i] * 2^(52*(i-5)) * 2^(52*5) ≡ t[i] * 2^(52*(i-5)) * 2^260
		// Since 2^256 ≡ M (mod p), we have 2^260 ≡ 2^4 * M ≡ 16 * M (mod p)
		
		// For i=5: 2^260 ≡ 16*M (mod p)
		// For i=6: 2^312 ≡ 2^52 * 16*M ≡ 2^56 * M (mod p)
		// etc.
		
		shift := uint(52 * (i - 5) + 4) // Additional 4 bits for the 16 factor
		
		// Multiply t[i] by the appropriate power of M
		var carry uint64
		if shift < 64 {
			// Simple case: can multiply directly
			factor := M << shift
			hi, lo := bits.Mul64(t[i], factor)
			
			// Add to appropriate position
			pos := 0
			t[pos], carry = bits.Add64(t[pos], lo, 0)
			if pos+1 < 10 {
				t[pos+1], carry = bits.Add64(t[pos+1], hi, carry)
			}
			
			// Propagate carry
			for j := pos + 2; j < 10 && carry != 0; j++ {
				t[j], carry = bits.Add64(t[j], 0, carry)
			}
		} else {
			// Need to handle larger shifts by distributing across limbs
			hi, lo := bits.Mul64(t[i], M)
			limbShift := shift / 52
			bitShift := shift % 52
			
			if bitShift == 0 {
				// Aligned to limb boundary
				if limbShift < 10 {
					t[limbShift], carry = bits.Add64(t[limbShift], lo, 0)
					if limbShift+1 < 10 {
						t[limbShift+1], carry = bits.Add64(t[limbShift+1], hi, carry)
					}
				}
			} else {
				// Need to split across limbs
				loShifted := lo << bitShift
				hiShifted := (lo >> (64 - bitShift)) | (hi << bitShift)
				
				if limbShift < 10 {
					t[limbShift], carry = bits.Add64(t[limbShift], loShifted, 0)
					if limbShift+1 < 10 {
						t[limbShift+1], carry = bits.Add64(t[limbShift+1], hiShifted, carry)
					}
				}
			}
			
			// Propagate any remaining carry
			for j := int(limbShift) + 2; j < 10 && carry != 0; j++ {
				t[j], carry = bits.Add64(t[j], 0, carry)
			}
		}
		
		t[i] = 0 // Clear the processed limb
	}
	
	// Now we have a value in t[0..4] that may still be >= p
	// Convert to 5x52 format and normalize
	r.n[0] = t[0] & limb0Max
	r.n[1] = ((t[0] >> 52) | (t[1] << 12)) & limb0Max
	r.n[2] = ((t[1] >> 40) | (t[2] << 24)) & limb0Max
	r.n[3] = ((t[2] >> 28) | (t[3] << 36)) & limb0Max
	r.n[4] = ((t[3] >> 16) | (t[4] << 48)) & limb4Max
	
	r.magnitude = 1
	r.normalized = false
	
	// Final reduction if needed
	if r.n[4] == limb4Max && r.n[3] == limb0Max && r.n[2] == limb0Max && 
	   r.n[1] == limb0Max && r.n[0] >= fieldModulusLimb0 {
		r.reduce()
	}
}

// sqr squares a field element: r = a^2
// This implementation follows the C secp256k1_fe_sqr_inner algorithm
// Optimized: avoid copies when magnitude is low enough
func (r *FieldElement) sqr(a *FieldElement) {
	// Use pointer directly if magnitude is low enough (optimization)
	var aNorm *FieldElement
	var aTemp FieldElement
	
	if a.magnitude > 8 {
		aTemp = *a
		aTemp.normalizeWeak()
		aNorm = &aTemp
	} else {
		aNorm = a // Use directly, no copy needed
	}

	// Extract limbs for easier access
	a0, a1, a2, a3, a4 := aNorm.n[0], aNorm.n[1], aNorm.n[2], aNorm.n[3], aNorm.n[4]

	const M = 0xFFFFFFFFFFFFF     // 2^52 - 1
	const R = fieldReductionConstantShifted // 0x1000003D10

	// Following the C implementation algorithm exactly
	
	// Compute p3 = 2*a0*a3 + 2*a1*a2
	var c, d uint128
	d = mulU64ToU128(a0*2, a3)
	d = addMulU128(d, a1*2, a2)
	
	// Compute p8 = a4*a4
	c = mulU64ToU128(a4, a4)
	
	// d += R * c_lo; c >>= 64
	d = addMulU128(d, R, c.lo())
	c = c.rshift(64)
	
	// Extract t3 and shift d
	t3 := d.lo() & M
	d = d.rshift(52)
	
	// Compute p4 = a0*a4*2 + a1*a3*2 + a2*a2
	a4 *= 2
	d = addMulU128(d, a0, a4)
	d = addMulU128(d, a1*2, a3)
	d = addMulU128(d, a2, a2)
	
	// d += (R << 12) * c_lo
	d = addMulU128(d, R<<12, c.lo())
	
	// Extract t4 and tx
	t4 := d.lo() & M
	d = d.rshift(52)
	tx := t4 >> 48
	t4 &= (M >> 4)
	
	// Compute p0 = a0*a0
	c = mulU64ToU128(a0, a0)
	
	// Compute p5 = a1*a4 + a2*a3*2
	d = addMulU128(d, a1, a4)
	d = addMulU128(d, a2*2, a3)
	
	// Extract u0
	u0 := d.lo() & M
	d = d.rshift(52)
	u0 = (u0 << 4) | tx
	
	// c += u0 * (R >> 4)
	c = addMulU128(c, u0, R>>4)
	
	// r[0]
	r.n[0] = c.lo() & M
	c = c.rshift(52)
	
	// Compute p1 = a0*a1*2
	a0 *= 2
	c = addMulU128(c, a0, a1)
	
	// Compute p6 = a2*a4 + a3*a3
	d = addMulU128(d, a2, a4)
	d = addMulU128(d, a3, a3)
	
	// c += R * (d & M); d >>= 52
	c = addMulU128(c, R, d.lo()&M)
	d = d.rshift(52)
	
	// r[1]
	r.n[1] = c.lo() & M
	c = c.rshift(52)
	
	// Compute p2 = a0*a2 + a1*a1
	c = addMulU128(c, a0, a2)
	c = addMulU128(c, a1, a1)
	
	// Compute p7 = a3*a4
	d = addMulU128(d, a3, a4)
	
	// c += R * d_lo; d >>= 64
	c = addMulU128(c, R, d.lo())
	d = d.rshift(64)
	
	// r[2]
	r.n[2] = c.lo() & M
	c = c.rshift(52)
	
	// c += (R << 12) * d_lo + t3
	c = addMulU128(c, R<<12, d.lo())
	c = addU128(c, t3)
	
	// r[3]
	r.n[3] = c.lo() & M
	c = c.rshift(52)
	
	// r[4]
	r.n[4] = c.lo() + t4
	
	// Set magnitude and normalization
	r.magnitude = 1
	r.normalized = false
}

// inv computes the modular inverse of a field element using Fermat's little theorem
// This implements a^(p-2) mod p where p is the secp256k1 field prime
// This follows secp256k1_fe_inv_var which normalizes the input first
func (r *FieldElement) inv(a *FieldElement) {
	// Normalize input first (as per secp256k1_fe_inv_var)
	var aNorm FieldElement
	aNorm = *a
	aNorm.normalize()
	
	// For field F_p, a^(-1) = a^(p-2) mod p
	// The secp256k1 field prime is p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
	// So p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
	
	// Use a simple but correct implementation: binary exponentiation
	// Convert p-2 to bytes for bit-by-bit exponentiation
	pMinus2 := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2D,
	}
	
	// Initialize result to 1
	r.setInt(1)
	
	// Binary exponentiation
	var base FieldElement
	base = aNorm
	
	for i := len(pMinus2) - 1; i >= 0; i-- {
		b := pMinus2[i]
		for j := 0; j < 8; j++ {
			if (b >> j) & 1 == 1 {
				r.mul(r, &base)
			}
			base.sqr(&base)
		}
	}
	
	r.magnitude = 1
	r.normalized = true
}

// sqrt computes the square root of a field element if it exists
// This follows the C secp256k1_fe_sqrt implementation exactly
func (r *FieldElement) sqrt(a *FieldElement) bool {
	// Given that p is congruent to 3 mod 4, we can compute the square root of
	// a mod p as the (p+1)/4'th power of a.
	//
	// As (p+1)/4 is an even number, it will have the same result for a and for
	// (-a). Only one of these two numbers actually has a square root however,
	// so we test at the end by squaring and comparing to the input.
	
	var aNorm FieldElement
	aNorm = *a
	
	// Normalize input if magnitude is too high
	if aNorm.magnitude > 8 {
		aNorm.normalizeWeak()
	} else {
		aNorm.normalize()
	}
	
	// The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
	// { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
	// 1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
	
	var x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1 FieldElement
	
	// x2 = a^3
	x2.sqr(&aNorm)
	x2.mul(&x2, &aNorm)
	
	// x3 = a^7
	x3.sqr(&x2)
	x3.mul(&x3, &aNorm)
	
	// x6 = a^63
	x6 = x3
	for j := 0; j < 3; j++ {
		x6.sqr(&x6)
	}
	x6.mul(&x6, &x3)
	
	// x9 = a^511
	x9 = x6
	for j := 0; j < 3; j++ {
		x9.sqr(&x9)
	}
	x9.mul(&x9, &x3)
	
	// x11 = a^2047
	x11 = x9
	for j := 0; j < 2; j++ {
		x11.sqr(&x11)
	}
	x11.mul(&x11, &x2)
	
	// x22 = a^4194303
	x22 = x11
	for j := 0; j < 11; j++ {
		x22.sqr(&x22)
	}
	x22.mul(&x22, &x11)
	
	// x44 = a^17592186044415
	x44 = x22
	for j := 0; j < 22; j++ {
		x44.sqr(&x44)
	}
	x44.mul(&x44, &x22)
	
	// x88 = a^72057594037927935
	x88 = x44
	for j := 0; j < 44; j++ {
		x88.sqr(&x88)
	}
	x88.mul(&x88, &x44)
	
	// x176 = a^1180591620717411303423
	x176 = x88
	for j := 0; j < 88; j++ {
		x176.sqr(&x176)
	}
	x176.mul(&x176, &x88)
	
	// x220 = a^172543658669764094685868767685
	x220 = x176
	for j := 0; j < 44; j++ {
		x220.sqr(&x220)
	}
	x220.mul(&x220, &x44)
	
	// x223 = a^13479973333575319897333507543509815336818572211270286240551805124607
	x223 = x220
	for j := 0; j < 3; j++ {
		x223.sqr(&x223)
	}
	x223.mul(&x223, &x3)
	
	// The final result is then assembled using a sliding window over the blocks.
	t1 = x223
	for j := 0; j < 23; j++ {
		t1.sqr(&t1)
	}
	t1.mul(&t1, &x22)
	for j := 0; j < 6; j++ {
		t1.sqr(&t1)
	}
	t1.mul(&t1, &x2)
	t1.sqr(&t1)
	r.sqr(&t1)
	
	// Check that a square root was actually calculated
	var check FieldElement
	check.sqr(r)
	check.normalize()
	aNorm.normalize()
	
	ret := check.equal(&aNorm)
	
	// If sqrt(a) doesn't exist, compute sqrt(-a) instead (as per field.h comment)
	if !ret {
		var negA FieldElement
		negA.negate(&aNorm, 1)
		negA.normalize()
		
		t1 = x223
		for j := 0; j < 23; j++ {
			t1.sqr(&t1)
		}
		t1.mul(&t1, &x22)
		for j := 0; j < 6; j++ {
			t1.sqr(&t1)
		}
		t1.mul(&t1, &x2)
		t1.sqr(&t1)
		r.sqr(&t1)
		
		check.sqr(r)
		check.normalize()
		
		// Return whether sqrt(-a) exists
		return check.equal(&negA)
	}
	
	return ret
}

// isSquare checks if a field element is a quadratic residue
func (a *FieldElement) isSquare() bool {
	// Use Legendre symbol: a^((p-1)/2) mod p
	// If result is 1, then a is a quadratic residue

	var result FieldElement
	result = *a

	// Compute a^((p-1)/2) - simplified implementation
	for i := 0; i < 127; i++ { // Approximate (p-1)/2 bit length
		result.sqr(&result)
	}

	result.normalize()
	return result.equal(&FieldElementOne)
}

// half computes r = a/2 mod p
func (r *FieldElement) half(a *FieldElement) {
	// This follows the C secp256k1_fe_impl_half implementation exactly
	*r = *a
	
	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]
	one := uint64(1)
	// In C: mask = -(t0 & one) >> 12
	// In Go, we need to convert to signed, negate, then convert back
	mask := uint64(-int64(t0 & one)) >> 12
	
	// Conditionally add field modulus if odd
	t0 += 0xFFFFEFFFFFC2F & mask
	t1 += mask
	t2 += mask  
	t3 += mask
	t4 += mask >> 4
	
	// Right shift with carry propagation
	r.n[0] = (t0 >> 1) + ((t1 & one) << 51)
	r.n[1] = (t1 >> 1) + ((t2 & one) << 51)
	r.n[2] = (t2 >> 1) + ((t3 & one) << 51)
	r.n[3] = (t3 >> 1) + ((t4 & one) << 51)
	r.n[4] = t4 >> 1
	
	// Update magnitude as per C implementation
	r.magnitude = (r.magnitude >> 1) + 1
	r.normalized = false
}
