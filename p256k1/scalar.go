package p256k1

import (
	"crypto/subtle"
	"math/bits"
	"unsafe"
)

// Scalar represents a scalar value modulo the secp256k1 group order.
// Uses 4 uint64 limbs to represent a 256-bit scalar.
type Scalar struct {
	d [4]uint64
}

// Scalar constants from the C implementation
const (
	// Limbs of the secp256k1 order n
	scalarN0 = 0xBFD25E8CD0364141
	scalarN1 = 0xBAAEDCE6AF48A03B
	scalarN2 = 0xFFFFFFFFFFFFFFFE
	scalarN3 = 0xFFFFFFFFFFFFFFFF

	// Limbs of 2^256 minus the secp256k1 order (complement constants)
	scalarNC0 = 0x402DA1732FC9BEBF // ~scalarN0 + 1
	scalarNC1 = 0x4551231950B75FC4 // ~scalarN1
	scalarNC2 = 0x0000000000000001 // 1

	// Limbs of half the secp256k1 order
	scalarNH0 = 0xDFE92F46681B20A0
	scalarNH1 = 0x5D576E7357A4501D
	scalarNH2 = 0xFFFFFFFFFFFFFFFF
	scalarNH3 = 0x7FFFFFFFFFFFFFFF
)

// Scalar element constants
var (
	// ScalarZero represents the scalar 0
	ScalarZero = Scalar{d: [4]uint64{0, 0, 0, 0}}

	// ScalarOne represents the scalar 1
	ScalarOne = Scalar{d: [4]uint64{1, 0, 0, 0}}
)

// setInt sets a scalar to a small integer value
func (r *Scalar) setInt(v uint) {
	r.d[0] = uint64(v)
	r.d[1] = 0
	r.d[2] = 0
	r.d[3] = 0
}

// setB32 sets a scalar from a 32-byte big-endian array
func (r *Scalar) setB32(b []byte) bool {
	if len(b) != 32 {
		panic("scalar byte array must be 32 bytes")
	}

	// Convert from big-endian bytes to uint64 limbs
	r.d[0] = uint64(b[31]) | uint64(b[30])<<8 | uint64(b[29])<<16 | uint64(b[28])<<24 |
		uint64(b[27])<<32 | uint64(b[26])<<40 | uint64(b[25])<<48 | uint64(b[24])<<56
	r.d[1] = uint64(b[23]) | uint64(b[22])<<8 | uint64(b[21])<<16 | uint64(b[20])<<24 |
		uint64(b[19])<<32 | uint64(b[18])<<40 | uint64(b[17])<<48 | uint64(b[16])<<56
	r.d[2] = uint64(b[15]) | uint64(b[14])<<8 | uint64(b[13])<<16 | uint64(b[12])<<24 |
		uint64(b[11])<<32 | uint64(b[10])<<40 | uint64(b[9])<<48 | uint64(b[8])<<56
	r.d[3] = uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56

	// Check if the scalar overflows the group order
	overflow := r.checkOverflow()
	if overflow {
		r.reduce(1)
	}

	return overflow
}

// setB32Seckey sets a scalar from a 32-byte secret key, returns true if valid
func (r *Scalar) setB32Seckey(b []byte) bool {
	overflow := r.setB32(b)
	return !r.isZero() && !overflow
}

// getB32 converts a scalar to a 32-byte big-endian array
func (r *Scalar) getB32(b []byte) {
	if len(b) != 32 {
		panic("scalar byte array must be 32 bytes")
	}

	// Convert from uint64 limbs to big-endian bytes
	b[31] = byte(r.d[0])
	b[30] = byte(r.d[0] >> 8)
	b[29] = byte(r.d[0] >> 16)
	b[28] = byte(r.d[0] >> 24)
	b[27] = byte(r.d[0] >> 32)
	b[26] = byte(r.d[0] >> 40)
	b[25] = byte(r.d[0] >> 48)
	b[24] = byte(r.d[0] >> 56)

	b[23] = byte(r.d[1])
	b[22] = byte(r.d[1] >> 8)
	b[21] = byte(r.d[1] >> 16)
	b[20] = byte(r.d[1] >> 24)
	b[19] = byte(r.d[1] >> 32)
	b[18] = byte(r.d[1] >> 40)
	b[17] = byte(r.d[1] >> 48)
	b[16] = byte(r.d[1] >> 56)

	b[15] = byte(r.d[2])
	b[14] = byte(r.d[2] >> 8)
	b[13] = byte(r.d[2] >> 16)
	b[12] = byte(r.d[2] >> 24)
	b[11] = byte(r.d[2] >> 32)
	b[10] = byte(r.d[2] >> 40)
	b[9] = byte(r.d[2] >> 48)
	b[8] = byte(r.d[2] >> 56)

	b[7] = byte(r.d[3])
	b[6] = byte(r.d[3] >> 8)
	b[5] = byte(r.d[3] >> 16)
	b[4] = byte(r.d[3] >> 24)
	b[3] = byte(r.d[3] >> 32)
	b[2] = byte(r.d[3] >> 40)
	b[1] = byte(r.d[3] >> 48)
	b[0] = byte(r.d[3] >> 56)
}

// checkOverflow checks if the scalar is >= the group order
func (r *Scalar) checkOverflow() bool {
	yes := 0
	no := 0

	// Check each limb from most significant to least significant
	if r.d[3] < scalarN3 {
		no = 1
	}
	if r.d[3] > scalarN3 {
		yes = 1
	}

	if r.d[2] < scalarN2 {
		no |= (yes ^ 1)
	}
	if r.d[2] > scalarN2 {
		yes |= (no ^ 1)
	}

	if r.d[1] < scalarN1 {
		no |= (yes ^ 1)
	}
	if r.d[1] > scalarN1 {
		yes |= (no ^ 1)
	}

	if r.d[0] >= scalarN0 {
		yes |= (no ^ 1)
	}

	return yes != 0
}

// reduce reduces the scalar modulo the group order
func (r *Scalar) reduce(overflow int) {
	if overflow < 0 || overflow > 1 {
		panic("overflow must be 0 or 1")
	}

	// Use 128-bit arithmetic for the reduction
	var t uint128

	// d[0] += overflow * scalarNC0
	t = uint128FromU64(r.d[0])
	t = t.addU64(uint64(overflow) * scalarNC0)
	r.d[0] = t.lo()
	t = t.rshift(64)

	// d[1] += overflow * scalarNC1 + carry
	t = t.addU64(r.d[1])
	t = t.addU64(uint64(overflow) * scalarNC1)
	r.d[1] = t.lo()
	t = t.rshift(64)

	// d[2] += overflow * scalarNC2 + carry
	t = t.addU64(r.d[2])
	t = t.addU64(uint64(overflow) * scalarNC2)
	r.d[2] = t.lo()
	t = t.rshift(64)

	// d[3] += carry (scalarNC3 = 0)
	t = t.addU64(r.d[3])
	r.d[3] = t.lo()
}

// add adds two scalars: r = a + b, returns overflow
func (r *Scalar) add(a, b *Scalar) bool {
	var carry uint64

	r.d[0], carry = bits.Add64(a.d[0], b.d[0], 0)
	r.d[1], carry = bits.Add64(a.d[1], b.d[1], carry)
	r.d[2], carry = bits.Add64(a.d[2], b.d[2], carry)
	r.d[3], carry = bits.Add64(a.d[3], b.d[3], carry)

	overflow := carry != 0 || r.checkOverflow()
	if overflow {
		r.reduce(1)
	}

	return overflow
}

// sub subtracts two scalars: r = a - b
func (r *Scalar) sub(a, b *Scalar) {
	// Compute a - b = a + (-b)
	var negB Scalar
	negB.negate(b)
	*r = *a
	r.add(r, &negB)
}

// mul multiplies two scalars: r = a * b
func (r *Scalar) mul(a, b *Scalar) {
	// Compute full 512-bit product using all 16 cross products
	var l [8]uint64
	r.mul512(l[:], a, b)
	r.reduce512(l[:])
}

// mul512 computes the 512-bit product of two scalars (from C implementation)
func (r *Scalar) mul512(l8 []uint64, a, b *Scalar) {
	// 160-bit accumulator (c0, c1, c2)
	var c0, c1 uint64
	var c2 uint32

	// Helper macros translated from C
	muladd := func(ai, bi uint64) {
		hi, lo := bits.Mul64(ai, bi)
		var carry uint64
		c0, carry = bits.Add64(c0, lo, 0)
		c1, carry = bits.Add64(c1, hi, carry)
		c2 += uint32(carry)
	}

	muladdFast := func(ai, bi uint64) {
		hi, lo := bits.Mul64(ai, bi)
		var carry uint64
		c0, carry = bits.Add64(c0, lo, 0)
		c1 += hi + carry
	}

	extract := func() uint64 {
		result := c0
		c0 = c1
		c1 = uint64(c2)
		c2 = 0
		return result
	}

	extractFast := func() uint64 {
		result := c0
		c0 = c1
		c1 = 0
		return result
	}

	// l8[0..7] = a[0..3] * b[0..3] (following C implementation exactly)
	muladdFast(a.d[0], b.d[0])
	l8[0] = extractFast()

	muladd(a.d[0], b.d[1])
	muladd(a.d[1], b.d[0])
	l8[1] = extract()

	muladd(a.d[0], b.d[2])
	muladd(a.d[1], b.d[1])
	muladd(a.d[2], b.d[0])
	l8[2] = extract()

	muladd(a.d[0], b.d[3])
	muladd(a.d[1], b.d[2])
	muladd(a.d[2], b.d[1])
	muladd(a.d[3], b.d[0])
	l8[3] = extract()

	muladd(a.d[1], b.d[3])
	muladd(a.d[2], b.d[2])
	muladd(a.d[3], b.d[1])
	l8[4] = extract()

	muladd(a.d[2], b.d[3])
	muladd(a.d[3], b.d[2])
	l8[5] = extract()

	muladdFast(a.d[3], b.d[3])
	l8[6] = extractFast()
	l8[7] = c0
}

// reduce512 reduces a 512-bit value to 256-bit (from C implementation)
func (r *Scalar) reduce512(l []uint64) {
	// 160-bit accumulator
	var c0, c1 uint64
	var c2 uint32

	// Extract upper 256 bits
	n0, n1, n2, n3 := l[4], l[5], l[6], l[7]

	// Helper macros
	muladd := func(ai, bi uint64) {
		hi, lo := bits.Mul64(ai, bi)
		var carry uint64
		c0, carry = bits.Add64(c0, lo, 0)
		c1, carry = bits.Add64(c1, hi, carry)
		c2 += uint32(carry)
	}

	muladdFast := func(ai, bi uint64) {
		hi, lo := bits.Mul64(ai, bi)
		var carry uint64
		c0, carry = bits.Add64(c0, lo, 0)
		c1 += hi + carry
	}

	sumadd := func(a uint64) {
		var carry uint64
		c0, carry = bits.Add64(c0, a, 0)
		c1, carry = bits.Add64(c1, 0, carry)
		c2 += uint32(carry)
	}

	sumaddFast := func(a uint64) {
		var carry uint64
		c0, carry = bits.Add64(c0, a, 0)
		c1 += carry
	}

	extract := func() uint64 {
		result := c0
		c0 = c1
		c1 = uint64(c2)
		c2 = 0
		return result
	}

	extractFast := func() uint64 {
		result := c0
		c0 = c1
		c1 = 0
		return result
	}

	// Reduce 512 bits into 385 bits
	// m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C
	c0 = l[0]
	c1 = 0
	c2 = 0
	muladdFast(n0, scalarNC0)
	m0 := extractFast()

	sumaddFast(l[1])
	muladd(n1, scalarNC0)
	muladd(n0, scalarNC1)
	m1 := extract()

	sumadd(l[2])
	muladd(n2, scalarNC0)
	muladd(n1, scalarNC1)
	sumadd(n0)
	m2 := extract()

	sumadd(l[3])
	muladd(n3, scalarNC0)
	muladd(n2, scalarNC1)
	sumadd(n1)
	m3 := extract()

	muladd(n3, scalarNC1)
	sumadd(n2)
	m4 := extract()

	sumaddFast(n3)
	m5 := extractFast()
	m6 := uint32(c0)

	// Reduce 385 bits into 258 bits
	// p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C
	c0 = m0
	c1 = 0
	c2 = 0
	muladdFast(m4, scalarNC0)
	p0 := extractFast()

	sumaddFast(m1)
	muladd(m5, scalarNC0)
	muladd(m4, scalarNC1)
	p1 := extract()

	sumadd(m2)
	muladd(uint64(m6), scalarNC0)
	muladd(m5, scalarNC1)
	sumadd(m4)
	p2 := extract()

	sumaddFast(m3)
	muladdFast(uint64(m6), scalarNC1)
	sumaddFast(m5)
	p3 := extractFast()
	p4 := uint32(c0 + uint64(m6))

	// Reduce 258 bits into 256 bits
	// r[0..3] = p[0..3] + p[4] * SECP256K1_N_C
	var t uint128

	t = uint128FromU64(p0)
	t = t.addMul(scalarNC0, uint64(p4))
	r.d[0] = t.lo()
	t = t.rshift(64)

	t = t.addU64(p1)
	t = t.addMul(scalarNC1, uint64(p4))
	r.d[1] = t.lo()
	t = t.rshift(64)

	t = t.addU64(p2)
	t = t.addU64(uint64(p4))
	r.d[2] = t.lo()
	t = t.rshift(64)

	t = t.addU64(p3)
	r.d[3] = t.lo()
	c := t.hi()

	// Final reduction
	r.reduce(int(c) + boolToInt(r.checkOverflow()))
}

// negate negates a scalar: r = -a
func (r *Scalar) negate(a *Scalar) {
	// r = n - a where n is the group order
	var borrow uint64

	r.d[0], borrow = bits.Sub64(scalarN0, a.d[0], 0)
	r.d[1], borrow = bits.Sub64(scalarN1, a.d[1], borrow)
	r.d[2], borrow = bits.Sub64(scalarN2, a.d[2], borrow)
	r.d[3], _ = bits.Sub64(scalarN3, a.d[3], borrow)
}

// inverse computes the modular inverse of a scalar
func (r *Scalar) inverse(a *Scalar) {
	// Use Fermat's little theorem: a^(-1) = a^(n-2) mod n
	// where n is the group order (which is prime)

	// Use binary exponentiation with n-2
	var exp Scalar
	var borrow uint64
	exp.d[0], borrow = bits.Sub64(scalarN0, 2, 0)
	exp.d[1], borrow = bits.Sub64(scalarN1, 0, borrow)
	exp.d[2], borrow = bits.Sub64(scalarN2, 0, borrow)
	exp.d[3], _ = bits.Sub64(scalarN3, 0, borrow)

	r.exp(a, &exp)
}

// exp computes r = a^b mod n using binary exponentiation
func (r *Scalar) exp(a, b *Scalar) {
	*r = ScalarOne
	base := *a

	for i := 0; i < 4; i++ {
		limb := b.d[i]
		for j := 0; j < 64; j++ {
			if limb&1 != 0 {
				r.mul(r, &base)
			}
			base.mul(&base, &base)
			limb >>= 1
		}
	}
}

// half computes r = a/2 mod n
func (r *Scalar) half(a *Scalar) {
	*r = *a

	if r.d[0]&1 == 0 {
		// Even case: simple right shift
		r.d[0] = (r.d[0] >> 1) | ((r.d[1] & 1) << 63)
		r.d[1] = (r.d[1] >> 1) | ((r.d[2] & 1) << 63)
		r.d[2] = (r.d[2] >> 1) | ((r.d[3] & 1) << 63)
		r.d[3] = r.d[3] >> 1
	} else {
		// Odd case: add n then divide by 2
		var carry uint64
		r.d[0], carry = bits.Add64(r.d[0], scalarN0, 0)
		r.d[1], carry = bits.Add64(r.d[1], scalarN1, carry)
		r.d[2], carry = bits.Add64(r.d[2], scalarN2, carry)
		r.d[3], _ = bits.Add64(r.d[3], scalarN3, carry)

		// Now divide by 2
		r.d[0] = (r.d[0] >> 1) | ((r.d[1] & 1) << 63)
		r.d[1] = (r.d[1] >> 1) | ((r.d[2] & 1) << 63)
		r.d[2] = (r.d[2] >> 1) | ((r.d[3] & 1) << 63)
		r.d[3] = r.d[3] >> 1
	}
}

// isZero returns true if the scalar is zero
func (r *Scalar) isZero() bool {
	return (r.d[0] | r.d[1] | r.d[2] | r.d[3]) == 0
}

// isOne returns true if the scalar is one
func (r *Scalar) isOne() bool {
	return r.d[0] == 1 && r.d[1] == 0 && r.d[2] == 0 && r.d[3] == 0
}

// isEven returns true if the scalar is even
func (r *Scalar) isEven() bool {
	return r.d[0]&1 == 0
}

// isHigh returns true if the scalar is > n/2
func (r *Scalar) isHigh() bool {
	var yes, no int

	if r.d[3] < scalarNH3 {
		no = 1
	}
	if r.d[3] > scalarNH3 {
		yes = 1
	}

	if r.d[2] < scalarNH2 {
		no |= (yes ^ 1)
	}
	if r.d[2] > scalarNH2 {
		yes |= (no ^ 1)
	}

	if r.d[1] < scalarNH1 {
		no |= (yes ^ 1)
	}
	if r.d[1] > scalarNH1 {
		yes |= (no ^ 1)
	}

	if r.d[0] > scalarNH0 {
		yes |= (no ^ 1)
	}

	return yes != 0
}

// condNegate conditionally negates the scalar if flag is true
func (r *Scalar) condNegate(flag int) {
	if flag != 0 {
		var neg Scalar
		neg.negate(r)
		*r = neg
	}
}

// equal returns true if two scalars are equal
func (r *Scalar) equal(a *Scalar) bool {
	return subtle.ConstantTimeCompare(
		(*[32]byte)(unsafe.Pointer(&r.d[0]))[:32],
		(*[32]byte)(unsafe.Pointer(&a.d[0]))[:32],
	) == 1
}

// getBits extracts count bits starting at offset
func (r *Scalar) getBits(offset, count uint) uint32 {
	if count == 0 || count > 32 {
		panic("count must be 1-32")
	}
	if offset+count > 256 {
		panic("offset + count must be <= 256")
	}

	limbIdx := offset / 64
	bitIdx := offset % 64

	if bitIdx+count <= 64 {
		// Bits are within a single limb
		return uint32((r.d[limbIdx] >> bitIdx) & ((1 << count) - 1))
	} else {
		// Bits span two limbs
		lowBits := 64 - bitIdx
		highBits := count - lowBits
		low := uint32((r.d[limbIdx] >> bitIdx) & ((1 << lowBits) - 1))
		high := uint32(r.d[limbIdx+1] & ((1 << highBits) - 1))
		return low | (high << lowBits)
	}
}

// cmov conditionally moves a scalar. If flag is true, r = a; otherwise r is unchanged.
func (r *Scalar) cmov(a *Scalar, flag int) {
	mask := uint64(-(int64(flag) & 1))
	r.d[0] ^= mask & (r.d[0] ^ a.d[0])
	r.d[1] ^= mask & (r.d[1] ^ a.d[1])
	r.d[2] ^= mask & (r.d[2] ^ a.d[2])
	r.d[3] ^= mask & (r.d[3] ^ a.d[3])
}

// clear clears a scalar to prevent leaking sensitive information
func (r *Scalar) clear() {
	memclear(unsafe.Pointer(&r.d[0]), unsafe.Sizeof(r.d))
}

// Helper types and functions for 128-bit arithmetic

type uint128 struct {
	low, high uint64
}

func uint128FromU64(x uint64) uint128 {
	return uint128{low: x, high: 0}
}

func (x uint128) addU64(y uint64) uint128 {
	low, carry := bits.Add64(x.low, y, 0)
	high := x.high + carry
	return uint128{low: low, high: high}
}

func (x uint128) addMul(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	low, carry := bits.Add64(x.low, lo, 0)
	high, _ := bits.Add64(x.high, hi, carry)
	return uint128{low: low, high: high}
}

func (x uint128) lo() uint64 {
	return x.low
}

func (x uint128) hi() uint64 {
	return x.high
}

func (x uint128) rshift(n uint) uint128 {
	if n >= 64 {
		return uint128{low: x.high >> (n - 64), high: 0}
	}
	return uint128{
		low: (x.low >> n) | (x.high << (64 - n)),
		high: x.high >> n,
	}
}

// Helper function to convert bool to int
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

