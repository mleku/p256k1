package p256k1

// GLV Endomorphism constants and functions
// Based on libsecp256k1's implementation

// Lambda is a primitive cube root of unity modulo the curve order n
// lambda^3 == 1 mod n, lambda^2 + lambda == -1 mod n
// Represented as 8 uint32 values converted to 4 uint64 values
var lambdaConstant = Scalar{
	d: [4]uint64{
		(uint64(0x5363AD4C) << 32) | uint64(0xC05C30E0),
		(uint64(0xA5261C02) << 32) | uint64(0x8812645A),
		(uint64(0x122E22EA) << 32) | uint64(0x20816678),
		(uint64(0xDF02967C) << 32) | uint64(0x1B23BD72),
	},
}

// Beta is a primitive cube root of unity modulo the field prime p
// beta^3 == 1 mod p, beta^2 + beta == -1 mod p
// Used to compute lambda*P = (beta*x, y)
// Represented as 8 uint32 values in big-endian format
var betaConstant FieldElement

func init() {
	// Beta constant: 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
	betaBytes := []byte{
		0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10,
		0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
		0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95,
		0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
	}
	betaConstant.setB32(betaBytes)
	betaConstant.normalize()
}

// Constants for scalar_split_lambda
// SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) maps to our d[0]=d1|d0, d[1]=d3|d2, d[2]=d5|d4, d[3]=d7|d6
var (
	// minus_b1 = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0xE4437ED6, 0x010E8828, 0x6F547FA9, 0x0ABFE4C3)
	minusB1 = Scalar{
		d: [4]uint64{
			(uint64(0x6F547FA9) << 32) | uint64(0x0ABFE4C3), // d[0] = d1|d0
			(uint64(0xE4437ED6) << 32) | uint64(0x010E8828), // d[1] = d3|d2  
			(uint64(0x00000000) << 32) | uint64(0x00000000), // d[2] = d5|d4
			(uint64(0x00000000) << 32) | uint64(0x00000000), // d[3] = d7|d6
		},
	}
	// minus_b2 = SECP256K1_SCALAR_CONST(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x8A280AC5, 0x0774346D, 0xD765CDA8, 0x3DB1562C)
	minusB2 = Scalar{
		d: [4]uint64{
			(uint64(0xD765CDA8) << 32) | uint64(0x3DB1562C), // d[0] = d1|d0
			(uint64(0x8A280AC5) << 32) | uint64(0x0774346D), // d[1] = d3|d2
			(uint64(0xFFFFFFFF) << 32) | uint64(0xFFFFFFFE), // d[2] = d5|d4
			(uint64(0xFFFFFFFF) << 32) | uint64(0xFFFFFFFF), // d[3] = d7|d6
		},
	}
	// g1 = SECP256K1_SCALAR_CONST(0x3086D221, 0xA7D46BCD, 0xE86C90E4, 0x9284EB15, 0x3DAA8A14, 0x71E8CA7F, 0xE893209A, 0x45DBB031)
	g1 = Scalar{
		d: [4]uint64{
			(uint64(0xE893209A) << 32) | uint64(0x45DBB031), // d[0] = d1|d0
			(uint64(0x3DAA8A14) << 32) | uint64(0x71E8CA7F), // d[1] = d3|d2
			(uint64(0xE86C90E4) << 32) | uint64(0x9284EB15), // d[2] = d5|d4
			(uint64(0x3086D221) << 32) | uint64(0xA7D46BCD), // d[3] = d7|d6
		},
	}
	// g2 = SECP256K1_SCALAR_CONST(0xE4437ED6, 0x010E8828, 0x6F547FA9, 0x0ABFE4C4, 0x221208AC, 0x9DF506C6, 0x1571B4AE, 0x8AC47F71)
	g2 = Scalar{
		d: [4]uint64{
			(uint64(0x1571B4AE) << 32) | uint64(0x8AC47F71), // d[0] = d1|d0
			(uint64(0x221208AC) << 32) | uint64(0x9DF506C6), // d[1] = d3|d2
			(uint64(0x6F547FA9) << 32) | uint64(0x0ABFE4C4), // d[2] = d5|d4
			(uint64(0xE4437ED6) << 32) | uint64(0x010E8828), // d[3] = d7|d6
		},
	}
)

// mulShiftVar multiplies two scalars and right-shifts the result by shift bits
// Returns round(k*g/2^shift)
func mulShiftVar(k, g *Scalar, shift uint) Scalar {
	// Compute 512-bit product
	var l [8]uint64
	var temp Scalar
	temp.mul512(l[:], k, g)
	
	// Extract result by shifting
	var result Scalar
	shiftlimbs := shift / 64
	shiftlow := shift % 64
	shifthigh := 64 - shiftlow
	
	if shift < 512 {
		result.d[0] = l[shiftlimbs] >> shiftlow
		if shift < 448 && shiftlow != 0 {
			result.d[0] |= l[shiftlimbs+1] << shifthigh
		}
	}
	if shift < 448 {
		result.d[1] = l[shiftlimbs+1] >> shiftlow
		if shift < 384 && shiftlow != 0 {
			result.d[1] |= l[shiftlimbs+2] << shifthigh
		}
	}
	if shift < 384 {
		result.d[2] = l[shiftlimbs+2] >> shiftlow
		if shift < 320 && shiftlow != 0 {
			result.d[2] |= l[shiftlimbs+3] << shifthigh
		}
	}
	if shift < 320 {
		result.d[3] = l[shiftlimbs+3] >> shiftlow
	}
	
	// Round: add 1 if bit (shift-1) is set
	// C code: secp256k1_scalar_cadd_bit(r, 0, (l[(shift - 1) >> 6] >> ((shift - 1) & 0x3f)) & 1);
	if shift > 0 {
		bitPos := (shift - 1) & 0x3f  // bit position within limb
		limbIdx := (shift - 1) >> 6   // which limb
		if limbIdx < 8 && (l[limbIdx]>>bitPos)&1 != 0 {
			// Add 1 to result (rounding up)
			var one Scalar
			one.setInt(1)
			result.add(&result, &one)
		}
	}
	
	return result
}

// scalarSplitLambda splits a scalar k into r1 and r2 such that:
//   r1 + lambda * r2 == k (mod n)
//   r1 and r2 are in range (-2^128, 2^128) mod n
// This matches the C implementation exactly: secp256k1_scalar_split_lambda
func scalarSplitLambda(r1, r2, k *Scalar) {
	var c1, c2 Scalar
	
	// C code: secp256k1_scalar_mul_shift_var(&c1, k, &g1, 384);
	// C code: secp256k1_scalar_mul_shift_var(&c2, k, &g2, 384);
	c1 = mulShiftVar(k, &g1, 384)
	c2 = mulShiftVar(k, &g2, 384)
	
	// C code: secp256k1_scalar_mul(&c1, &c1, &minus_b1);
	// C code: secp256k1_scalar_mul(&c2, &c2, &minus_b2);
	c1.mul(&c1, &minusB1)
	c2.mul(&c2, &minusB2)
	
	// C code: secp256k1_scalar_add(r2, &c1, &c2);
	r2.add(&c1, &c2)
	
	// C code: secp256k1_scalar_mul(r1, r2, &secp256k1_const_lambda);
	// C code: secp256k1_scalar_negate(r1, r1);
	// C code: secp256k1_scalar_add(r1, r1, k);
	r1.mul(r2, &lambdaConstant)
	r1.negate(r1)
	r1.add(r1, k)
}

// geMulLambda multiplies a point by lambda using the endomorphism:
//   lambda * (x, y) = (beta * x, y)
func geMulLambda(r *GroupElementAffine, a *GroupElementAffine) {
	*r = *a
	// Multiply x coordinate by beta
	r.x.mul(&r.x, &betaConstant)
	r.x.normalize()
}

// Constants for GLV + signed-digit ecmult_const
const (
	ecmultConstGroupSize = 5
	ecmultConstTableSize = 1 << (ecmultConstGroupSize - 1) // 16
	ecmultConstBits      = 130                              // Smallest multiple of 5 >= 129
	ecmultConstGroups    = (ecmultConstBits + ecmultConstGroupSize - 1) / ecmultConstGroupSize
)

// K constant for ECMULT_CONST_BITS=130
// K = (2^130 - 2^129 - 1)*(1 + lambda) mod n
var ecmultConstK = Scalar{
	d: [4]uint64{
		(uint64(0xa4e88a7d) << 32) | uint64(0xcb13034e),
		(uint64(0xc2bdd6bf) << 32) | uint64(0x7c118d6b),
		(uint64(0x589ae848) << 32) | uint64(0x26ba29e4),
		(uint64(0xb5c2c1dc) << 32) | uint64(0xde9798d9),
	},
}

// S_OFFSET = 2^128
// SECP256K1_SCALAR_CONST reorders parameters: d[0]=d1|d0, d[1]=d3|d2, d[2]=d5|d4, d[3]=d7|d6
// For 2^128 (bit 128), we need d[2] bit 0 set, which is d5=1, d4=0
// SECP256K1_SCALAR_CONST(0, 0, 0, 1, 0, 0, 0, 0) gives d[2]=2^32, not 2^128!
// For 2^128: SECP256K1_SCALAR_CONST(0, 0, 1, 0, 0, 0, 0, 0) -> d[2] = 1<<32|0 = 2^32... wait
// Actually: SECP256K1_SCALAR_CONST(0, 0, 0, 0, 1, 0, 0, 0) -> d[2] = 0<<32|1 = 1, which is bit 128
var sOffset = Scalar{
	d: [4]uint64{0, 0, 1, 0}, // d[2] = 1 means bit 128 is set
}

// signedDigitTableGet performs signed-digit table lookup
// Given a table of odd multiples [1*P, 3*P, ..., 15*P] and an n-bit value,
// returns the signed-digit representation C_n(n, P)
// This matches the ECMULT_CONST_TABLE_GET_GE macro exactly
func signedDigitTableGet(pre []GroupElementAffine, n uint32) GroupElementAffine {
	// C code: volatile unsigned int negative = ((n) >> (ECMULT_CONST_GROUP_SIZE - 1)) ^ 1;
	// If the top bit of n is 0, we want the negation.
	negative := ((n >> (ecmultConstGroupSize - 1)) ^ 1) != 0
	
	// Compute index: index = ((unsigned int)(-negative) ^ n) & ((1U << (ECMULT_CONST_GROUP_SIZE - 1)) - 1U)
	var negMask uint32
	if negative {
		negMask = 0xFFFFFFFF
	} else {
		negMask = 0
	}
	index := (negMask ^ n) & ((1 << (ecmultConstGroupSize - 1)) - 1)
	
	// Constant-time lookup - initialize with pre[0], then conditionally update using cmov
	var result GroupElementAffine
	result = pre[0]
	// C code: for (m = 1; m < ECMULT_CONST_TABLE_SIZE; m++) { secp256k1_fe_cmov(&(r)->x, &(pre)[m].x, m == index); ... }
	for i := uint32(1); i < ecmultConstTableSize; i++ {
		flag := 0
		if i == index {
			flag = 1
		}
		result.x.cmov(&pre[i].x, flag)
		result.y.cmov(&pre[i].y, flag)
	}
	
	// C code: (r)->infinity = 0;
	result.infinity = false
	
	// C code: secp256k1_fe_negate(&neg_y, &(r)->y, 1);
	// C code: secp256k1_fe_cmov(&(r)->y, &neg_y, negative);
	var negY FieldElement
	negY.negate(&result.y, 1)
	flag := 0
	if negative {
		flag = 1
	}
	result.y.cmov(&negY, flag)
	result.y.normalize()
	
	return result
}

// buildOddMultiplesTableWithGlobalZ builds a table of odd multiples with global Z
// Implements effective affine technique like C code: secp256k1_ecmult_odd_multiples_table + secp256k1_ge_table_set_globalz
func buildOddMultiplesTableWithGlobalZ(n int, aJac *GroupElementJacobian) ([]GroupElementAffine, *FieldElement) {
	if aJac.isInfinity() {
		return nil, nil
	}

	pre := make([]GroupElementAffine, n)
	zr := make([]FieldElement, n)

	// Build 2*a (called 'd' in C code)
	var d GroupElementJacobian
	d.double(aJac)

	// Use effective affine technique: work on isomorphic curve where d.z is the isomorphism constant
	// Set d_ge = affine representation of d (for faster additions)
	// C code: secp256k1_ge_set_xy(&d_ge, &d.x, &d.y);
	var dGe GroupElementAffine
	dGe.setXY(&d.x, &d.y)

	// Set pre[0] = a with z-inverse d.z (using setGEJ_zinv equivalent)
	// This represents a on the isomorphic curve
	// C code: secp256k1_ge_set_gej_zinv(&pre_a[0], a, &d.z);
	// Save d.z BEFORE calling inv (which modifies input)
	var dZ FieldElement
	dZ = d.z
	var dZInv FieldElement
	dZInv.inv(&d.z)
	var zi2, zi3 FieldElement
	zi2.sqr(&dZInv)
	zi3.mul(&zi2, &dZInv)
	pre[0].x.mul(&aJac.x, &zi2)
	pre[0].y.mul(&aJac.y, &zi3)
	pre[0].infinity = false
	zr[0] = dZ // Store z ratio (C code: zr[0] = d.z)

	// Build remaining odd multiples using effective affine additions
	// ai represents the current point in the isomorphic curve (Jacobian form)
	var ai GroupElementJacobian
	ai.setGE(&pre[0])
	// C code: ai.z = a->z; (line 98)
	ai.z = aJac.z

	// Build odd multiples: pre[i] = (2*i+1)*a
	for i := 1; i < n; i++ {
		// ai = ai + d_ge (in the isomorphic curve) - this is faster than full Jacobian addition
		// C code: secp256k1_gej_add_ge_var(&ai, &ai, &d_ge, &zr[i])
		// This computes zr[i] = h internally
		ai.addGEWithZR(&ai, &dGe, &zr[i])
		
		// Store x, y coordinates (affine representation on isomorphic curve)
		// C code: secp256k1_ge_set_xy(&pre_a[i], &ai.x, &ai.y)
		pre[i].x = ai.x
		pre[i].y = ai.y
		pre[i].infinity = false
	}

	// Apply ge_table_set_globalz equivalent: bring all points to same Z denominator
	// C code: secp256k1_ge_table_set_globalz(ECMULT_CONST_TABLE_SIZE, pre, zr)
	if n > 0 {
		i := n - 1
		// Ensure all y values are in weak normal form for fast negation (C code line 302)
		pre[i].y.normalizeWeak()
		
		var zs FieldElement
		zs = zr[i]  // zs = zr[n-1]
		
		// Work backwards, using z-ratios to scale x/y values
		// C code: while (i > 0) { ... secp256k1_ge_set_ge_zinv(&a[i], &a[i], &zs); }
		for i > 0 {
			if i != n-1 {
				// C code: secp256k1_fe_mul(&zs, &zs, &zr[i])
				// Multiply zs by zr[i] BEFORE decrementing i
				zs.mul(&zs, &zr[i])
			}
			i--
			
			// Scale pre[i] by zs inverse: pre[i] = pre[i] with z-inverse zs
			// C code: secp256k1_ge_set_ge_zinv(&a[i], &a[i], &zs)
			var zsInv FieldElement
			zsInv.inv(&zs)
			var zsInv2, zsInv3 FieldElement
			zsInv2.sqr(&zsInv)
			zsInv3.mul(&zsInv2, &zsInv)
			pre[i].x.mul(&pre[i].x, &zsInv2)
			pre[i].y.mul(&pre[i].y, &zsInv3)
		}
	}

	// Compute global_z = ai.z * d.z (undoing isomorphism)
	// C code: secp256k1_fe_mul(z, &ai.z, &d.z)
	var globalZ FieldElement
	globalZ.mul(&ai.z, &d.z)
	globalZ.normalize()
	
	return pre, &globalZ
}

func buildOddMultiplesTableSimple(n int, aJac *GroupElementJacobian) []GroupElementAffine {
	if aJac.isInfinity() {
		return nil
	}

	preJac := make([]GroupElementJacobian, n)
	preAff := make([]GroupElementAffine, n)

	// preJac[0] = 1*a
	preJac[0] = *aJac

	// d = 2*a
	var d GroupElementJacobian
	d.double(aJac)

	for i := 1; i < n; i++ {
		preJac[i].addVar(&preJac[i-1], &d)
	}

	// Batch convert to affine
	z := make([]FieldElement, n)
	for i := 0; i < n; i++ {
		z[i] = preJac[i].z
	}
	zInv := make([]FieldElement, n)
	batchInverse(zInv, z)

	for i := 0; i < n; i++ {
		var zi2, zi3 FieldElement
		zi2.sqr(&zInv[i])
		zi3.mul(&zi2, &zInv[i])
		preAff[i].x.mul(&preJac[i].x, &zi2)
		preAff[i].y.mul(&preJac[i].y, &zi3)
		preAff[i].infinity = false
	}

	return preAff
}

// ecmultConstGLV computes r = q * a using GLV endomorphism + signed-digit method
// This matches the C libsecp256k1 secp256k1_ecmult_const implementation exactly
func ecmultConstGLV(r *GroupElementJacobian, a *GroupElementAffine, q *Scalar) {
	// C code: if (secp256k1_ge_is_infinity(a)) { secp256k1_gej_set_infinity(r); return; }
	if a.isInfinity() {
		r.setInfinity()
		return
	}

	// Step 1: Compute v1 and v2 (C code lines 207-212)
	// secp256k1_scalar_add(&s, q, &secp256k1_ecmult_const_K);
	// secp256k1_scalar_half(&s, &s);
	// secp256k1_scalar_split_lambda(&v1, &v2, &s);
	// secp256k1_scalar_add(&v1, &v1, &S_OFFSET);
	// secp256k1_scalar_add(&v2, &v2, &S_OFFSET);
	var s, v1, v2 Scalar
	s.add(q, &ecmultConstK)
	s.half(&s)
	scalarSplitLambda(&v1, &v2, &s)
	v1.add(&v1, &sOffset)
	v2.add(&v2, &sOffset)

	// Step 2: Build precomputation tables (C code lines 228-232)
	// secp256k1_gej_set_ge(r, a);
	// secp256k1_ecmult_const_odd_multiples_table_globalz(pre_a, &global_z, r);
	// for (i = 0; i < ECMULT_CONST_TABLE_SIZE; i++) {
	//     secp256k1_ge_mul_lambda(&pre_a_lam[i], &pre_a[i]);
	// }
	var aJac GroupElementJacobian
	aJac.setGE(a)
	// TEMPORARILY use simple table building to isolate the bug
	preA := buildOddMultiplesTableSimple(ecmultConstTableSize, &aJac)
	var globalZ *FieldElement = nil  // No global Z correction for now
	
	preALam := make([]GroupElementAffine, ecmultConstTableSize)
	for i := 0; i < ecmultConstTableSize; i++ {
		geMulLambda(&preALam[i], &preA[i])
	}

	// Step 3: Main loop (C code lines 244-264)
	// This is the key difference - C processes both v1 and v2 in a SINGLE loop
	for group := ecmultConstGroups - 1; group >= 0; group-- {
		// C code: unsigned int bits1 = secp256k1_scalar_get_bits_var(&v1, group * ECMULT_CONST_GROUP_SIZE, ECMULT_CONST_GROUP_SIZE);
		// C code: unsigned int bits2 = secp256k1_scalar_get_bits_var(&v2, group * ECMULT_CONST_GROUP_SIZE, ECMULT_CONST_GROUP_SIZE);
		bitOffset := uint(group * ecmultConstGroupSize)
		bits1 := uint32(v1.getBits(bitOffset, ecmultConstGroupSize))
		bits2 := uint32(v2.getBits(bitOffset, ecmultConstGroupSize))
		
		// C code: ECMULT_CONST_TABLE_GET_GE(&t, pre_a, bits1);
		var t GroupElementAffine
		t = signedDigitTableGet(preA, bits1)
		
		if group == ecmultConstGroups-1 {
			// C code: secp256k1_gej_set_ge(r, &t);
			r.setGE(&t)
		} else {
			// C code: for (j = 0; j < ECMULT_CONST_GROUP_SIZE; ++j) { secp256k1_gej_double(r, r); }
			// C code: secp256k1_gej_add_ge(r, r, &t);
			for j := 0; j < ecmultConstGroupSize; j++ {
				r.double(r)
			}
			r.addGE(r, &t)
		}
		
		// C code: ECMULT_CONST_TABLE_GET_GE(&t, pre_a_lam, bits2);
		// C code: secp256k1_gej_add_ge(r, r, &t);
		t = signedDigitTableGet(preALam, bits2)
		r.addGE(r, &t)
	}

	// Step 4: Apply global Z correction (C code line 267)
	// C code: secp256k1_fe_mul(&r->z, &r->z, &global_z);
	if globalZ != nil && !globalZ.isZero() && !r.isInfinity() {
		r.z.mul(&r.z, globalZ)
		r.z.normalize()
	}
}

