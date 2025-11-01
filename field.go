package p256k1

import (
	"crypto/subtle"
	"errors"
	"unsafe"
)

// FieldElement represents a field element modulo the secp256k1 field prime (2^256 - 2^32 - 977).
// This implementation uses 5 uint64 limbs in base 2^52, ported from field_5x52.h
type FieldElement struct {
	// n represents the sum(i=0..4, n[i] << (i*52)) mod p
	// where p is the field modulus, 2^256 - 2^32 - 977
	n [5]uint64

	// Verification fields for debug builds
	magnitude  int  // magnitude of the field element
	normalized bool // whether the field element is normalized
}

// FieldElementStorage represents a field element in storage format (4 uint64 limbs)
type FieldElementStorage struct {
	n [4]uint64
}

// Field constants
const (
	// Field modulus reduction constant: 2^32 + 977
	fieldReductionConstant = 0x1000003D1
	// Reduction constant used in multiplication (shifted version)
	fieldReductionConstantShifted = 0x1000003D10

	// Maximum values for limbs
	limb0Max = 0xFFFFFFFFFFFFF // 2^52 - 1
	limb4Max = 0x0FFFFFFFFFFFF // 2^48 - 1

	// Field modulus limbs for comparison
	fieldModulusLimb0 = 0xFFFFEFFFFFC2F
	fieldModulusLimb1 = 0xFFFFFFFFFFFFF
	fieldModulusLimb2 = 0xFFFFFFFFFFFFF
	fieldModulusLimb3 = 0xFFFFFFFFFFFFF
	fieldModulusLimb4 = 0x0FFFFFFFFFFFF
)

// Field element constants
var (
	// FieldElementOne represents the field element 1
	FieldElementOne = FieldElement{
		n:          [5]uint64{1, 0, 0, 0, 0},
		magnitude:  1,
		normalized: true,
	}

	// FieldElementZero represents the field element 0
	FieldElementZero = FieldElement{
		n:          [5]uint64{0, 0, 0, 0, 0},
		magnitude:  0,
		normalized: true,
	}
)

// NewFieldElement creates a new field element
func NewFieldElement() *FieldElement {
	return &FieldElement{
		n:          [5]uint64{0, 0, 0, 0, 0},
		magnitude:  0,
		normalized: true,
	}
}

// setB32 sets a field element from a 32-byte big-endian array
func (r *FieldElement) setB32(b []byte) error {
	if len(b) != 32 {
		return errors.New("field element byte array must be 32 bytes")
	}

	// Convert from big-endian bytes to 5x52 limbs
	// First convert to 4x64 limbs then to 5x52
	var d [4]uint64
	for i := 0; i < 4; i++ {
		d[i] = uint64(b[31-8*i]) | uint64(b[30-8*i])<<8 | uint64(b[29-8*i])<<16 | uint64(b[28-8*i])<<24 |
			uint64(b[27-8*i])<<32 | uint64(b[26-8*i])<<40 | uint64(b[25-8*i])<<48 | uint64(b[24-8*i])<<56
	}

	// Convert from 4x64 to 5x52
	r.n[0] = d[0] & limb0Max
	r.n[1] = ((d[0] >> 52) | (d[1] << 12)) & limb0Max
	r.n[2] = ((d[1] >> 40) | (d[2] << 24)) & limb0Max
	r.n[3] = ((d[2] >> 28) | (d[3] << 36)) & limb0Max
	r.n[4] = (d[3] >> 16) & limb4Max

	r.magnitude = 1
	r.normalized = false

	return nil
}

// getB32 converts a field element to a 32-byte big-endian array
func (r *FieldElement) getB32(b []byte) {
	if len(b) != 32 {
		panic("field element byte array must be 32 bytes")
	}

	// Normalize first
	var normalized FieldElement
	normalized = *r
	normalized.normalize()

	// Convert from 5x52 to 4x64 limbs
	var d [4]uint64
	d[0] = normalized.n[0] | (normalized.n[1] << 52)
	d[1] = (normalized.n[1] >> 12) | (normalized.n[2] << 40)
	d[2] = (normalized.n[2] >> 24) | (normalized.n[3] << 28)
	d[3] = (normalized.n[3] >> 36) | (normalized.n[4] << 16)

	// Convert to big-endian bytes
	for i := 0; i < 4; i++ {
		b[31-8*i] = byte(d[i])
		b[30-8*i] = byte(d[i] >> 8)
		b[29-8*i] = byte(d[i] >> 16)
		b[28-8*i] = byte(d[i] >> 24)
		b[27-8*i] = byte(d[i] >> 32)
		b[26-8*i] = byte(d[i] >> 40)
		b[25-8*i] = byte(d[i] >> 48)
		b[24-8*i] = byte(d[i] >> 56)
	}
}

// normalize normalizes a field element to its canonical representation
func (r *FieldElement) normalize() {
	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]

	// Reduce t4 at the start so there will be at most a single carry from the first pass
	x := t4 >> 48
	t4 &= limb4Max

	// First pass ensures magnitude is 1
	t0 += x * fieldReductionConstant
	t1 += t0 >> 52
	t0 &= limb0Max
	t2 += t1 >> 52
	t1 &= limb0Max
	m := t1
	t3 += t2 >> 52
	t2 &= limb0Max
	m &= t2
	t4 += t3 >> 52
	t3 &= limb0Max
	m &= t3

	// Check if we need final reduction
	needReduction := 0
	if t4 == limb4Max && m == limb0Max && t0 >= fieldModulusLimb0 {
		needReduction = 1
	}
	x = (t4 >> 48) | uint64(needReduction)

	// Apply final reduction (always for constant-time behavior)
	t0 += uint64(x) * fieldReductionConstant
	t1 += t0 >> 52
	t0 &= limb0Max
	t2 += t1 >> 52
	t1 &= limb0Max
	t3 += t2 >> 52
	t2 &= limb0Max
	t4 += t3 >> 52
	t3 &= limb0Max

	// Mask off the possible multiple of 2^256 from the final reduction
	t4 &= limb4Max

	r.n[0], r.n[1], r.n[2], r.n[3], r.n[4] = t0, t1, t2, t3, t4
	r.magnitude = 1
	r.normalized = true
}

// normalizeWeak gives a field element magnitude 1 without full normalization
func (r *FieldElement) normalizeWeak() {
	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]

	// Reduce t4 at the start
	x := t4 >> 48
	t4 &= limb4Max

	// First pass ensures magnitude is 1
	t0 += x * fieldReductionConstant
	t1 += t0 >> 52
	t0 &= limb0Max
	t2 += t1 >> 52
	t1 &= limb0Max
	t3 += t2 >> 52
	t2 &= limb0Max
	t4 += t3 >> 52
	t3 &= limb0Max

	r.n[0], r.n[1], r.n[2], r.n[3], r.n[4] = t0, t1, t2, t3, t4
	r.magnitude = 1
}

// reduce performs modular reduction (simplified implementation)
func (r *FieldElement) reduce() {
	// For now, just normalize to ensure proper representation
	r.normalize()
}

// isZero returns true if the field element represents zero
func (r *FieldElement) isZero() bool {
	if !r.normalized {
		panic("field element must be normalized")
	}
	return r.n[0] == 0 && r.n[1] == 0 && r.n[2] == 0 && r.n[3] == 0 && r.n[4] == 0
}

// isOdd returns true if the field element is odd
func (r *FieldElement) isOdd() bool {
	if !r.normalized {
		panic("field element must be normalized")
	}
	return r.n[0]&1 == 1
}

// normalizesToZeroVar checks if the field element normalizes to zero
// This is a variable-time check (not constant-time)
// A field element normalizes to zero if all limbs are zero or if it equals the modulus
func (r *FieldElement) normalizesToZeroVar() bool {
	var t FieldElement
	t = *r
	t.normalize()
	return t.isZero()
}

// equal returns true if two field elements are equal
func (r *FieldElement) equal(a *FieldElement) bool {
	// Both must be normalized for comparison
	if !r.normalized || !a.normalized {
		panic("field elements must be normalized for comparison")
	}

	return subtle.ConstantTimeCompare(
		(*[40]byte)(unsafe.Pointer(&r.n[0]))[:40],
		(*[40]byte)(unsafe.Pointer(&a.n[0]))[:40],
	) == 1
}

// setInt sets a field element to a small integer value
func (r *FieldElement) setInt(a int) {
	if a < 0 || a > 0x7FFF {
		panic("value out of range")
	}

	r.n[0] = uint64(a)
	r.n[1] = 0
	r.n[2] = 0
	r.n[3] = 0
	r.n[4] = 0
	if a == 0 {
		r.magnitude = 0
	} else {
		r.magnitude = 1
	}
	r.normalized = true
}

// clear clears a field element to prevent leaking sensitive information
func (r *FieldElement) clear() {
	memclear(unsafe.Pointer(&r.n[0]), unsafe.Sizeof(r.n))
	r.magnitude = 0
	r.normalized = true
}

// negate negates a field element: r = -a
func (r *FieldElement) negate(a *FieldElement, m int) {
	if m < 0 || m > 31 {
		panic("magnitude out of range")
	}

	// r = p - a, where p is represented with appropriate magnitude
	r.n[0] = (2*uint64(m)+1)*fieldModulusLimb0 - a.n[0]
	r.n[1] = (2*uint64(m)+1)*fieldModulusLimb1 - a.n[1]
	r.n[2] = (2*uint64(m)+1)*fieldModulusLimb2 - a.n[2]
	r.n[3] = (2*uint64(m)+1)*fieldModulusLimb3 - a.n[3]
	r.n[4] = (2*uint64(m)+1)*fieldModulusLimb4 - a.n[4]

	r.magnitude = m + 1
	r.normalized = false
}

// add adds two field elements: r += a
func (r *FieldElement) add(a *FieldElement) {
	r.n[0] += a.n[0]
	r.n[1] += a.n[1]
	r.n[2] += a.n[2]
	r.n[3] += a.n[3]
	r.n[4] += a.n[4]

	r.magnitude += a.magnitude
	r.normalized = false
}

// sub subtracts a field element: r -= a
func (r *FieldElement) sub(a *FieldElement) {
	// To subtract, we add the negation
	var negA FieldElement
	negA.negate(a, a.magnitude)
	r.add(&negA)
}

// mulInt multiplies a field element by a small integer
func (r *FieldElement) mulInt(a int) {
	if a < 0 || a > 32 {
		panic("multiplier out of range")
	}

	ua := uint64(a)
	r.n[0] *= ua
	r.n[1] *= ua
	r.n[2] *= ua
	r.n[3] *= ua
	r.n[4] *= ua

	r.magnitude *= a
	r.normalized = false
}

// cmov conditionally moves a field element. If flag is true, r = a; otherwise r is unchanged.
func (r *FieldElement) cmov(a *FieldElement, flag int) {
	mask := uint64(-(int64(flag) & 1))
	r.n[0] ^= mask & (r.n[0] ^ a.n[0])
	r.n[1] ^= mask & (r.n[1] ^ a.n[1])
	r.n[2] ^= mask & (r.n[2] ^ a.n[2])
	r.n[3] ^= mask & (r.n[3] ^ a.n[3])
	r.n[4] ^= mask & (r.n[4] ^ a.n[4])

	// Update metadata conditionally
	if flag != 0 {
		r.magnitude = a.magnitude
		r.normalized = a.normalized
	}
}

// toStorage converts a field element to storage format
func (r *FieldElement) toStorage(s *FieldElementStorage) {
	// Normalize first
	var normalized FieldElement
	normalized = *r
	normalized.normalize()

	// Convert from 5x52 to 4x64
	s.n[0] = normalized.n[0] | (normalized.n[1] << 52)
	s.n[1] = (normalized.n[1] >> 12) | (normalized.n[2] << 40)
	s.n[2] = (normalized.n[2] >> 24) | (normalized.n[3] << 28)
	s.n[3] = (normalized.n[3] >> 36) | (normalized.n[4] << 16)
}

// fromStorage converts from storage format to field element
func (r *FieldElement) fromStorage(s *FieldElementStorage) {
	// Convert from 4x64 to 5x52
	r.n[0] = s.n[0] & limb0Max
	r.n[1] = ((s.n[0] >> 52) | (s.n[1] << 12)) & limb0Max
	r.n[2] = ((s.n[1] >> 40) | (s.n[2] << 24)) & limb0Max
	r.n[3] = ((s.n[2] >> 28) | (s.n[3] << 36)) & limb0Max
	r.n[4] = (s.n[3] >> 16) & limb4Max

	r.magnitude = 1
	r.normalized = false
}

// memclear clears memory to prevent leaking sensitive information
func memclear(ptr unsafe.Pointer, n uintptr) {
	// Use a volatile write to prevent the compiler from optimizing away the clear
	for i := uintptr(0); i < n; i++ {
		*(*byte)(unsafe.Pointer(uintptr(ptr) + i)) = 0
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// batchInverse computes the inverses of a slice of FieldElements.
func batchInverse(out []FieldElement, a []FieldElement) {
	n := len(a)
	if n == 0 {
		return
	}

	// This is a direct port of the batch inversion routine from btcec.
	// It uses Montgomery's trick to perform a batch inversion with only a
	// single inversion.
	s := make([]FieldElement, n)

	// s_i = a_0 * a_1 * ... * a_{i-1}
	s[0].setInt(1)
	for i := 1; i < n; i++ {
		s[i].mul(&s[i-1], &a[i-1])
	}

	// u = (a_0 * a_1 * ... * a_{n-1})^-1
	var u FieldElement
	u.mul(&s[n-1], &a[n-1])
	u.inv(&u)

	// out_i = (a_0 * ... * a_{i-1}) * (a_0 * ... * a_i)^-1
	//
	// Loop backwards to make it an in-place algorithm.
	for i := n - 1; i >= 0; i-- {
		out[i].mul(&u, &s[i])
		u.mul(&u, &a[i])
	}
}
