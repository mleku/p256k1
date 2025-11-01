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

	// Beta constant used in endomorphism optimization
	FieldElementBeta = FieldElement{
		n: [5]uint64{
			0x719501ee7ae96a2b, 0x9cf04975657c0710, 0x12f58995ac3434e9,
			0xc1396c286e64479e, 0x0000000000000000,
		},
		magnitude:  1,
		normalized: true,
	}
)

// NewFieldElement creates a new field element from a 32-byte big-endian array
func NewFieldElement(b32 []byte) (r *FieldElement, err error) {
	if len(b32) != 32 {
		return nil, errors.New("input must be 32 bytes")
	}

	r = &FieldElement{}
	r.setB32(b32)
	return r, nil
}

// setB32 sets a field element from a 32-byte big-endian array, reducing modulo p
func (r *FieldElement) setB32(a []byte) {
	// Convert from big-endian bytes to limbs
	r.n[0] = readBE64(a[24:32]) & limb0Max
	r.n[1] = (readBE64(a[16:24]) << 12) | (readBE64(a[24:32]) >> 52)
	r.n[1] &= limb0Max
	r.n[2] = (readBE64(a[8:16]) << 24) | (readBE64(a[16:24]) >> 40)
	r.n[2] &= limb0Max
	r.n[3] = (readBE64(a[0:8]) << 36) | (readBE64(a[8:16]) >> 28)
	r.n[3] &= limb0Max
	r.n[4] = readBE64(a[0:8]) >> 16

	r.magnitude = 1
	r.normalized = false

	// Reduce if necessary
	if r.n[4] == limb4Max && r.n[3] == limb0Max && r.n[2] == limb0Max &&
		r.n[1] == limb0Max && r.n[0] >= fieldModulusLimb0 {
		r.reduce()
	}
}

// getB32 converts a normalized field element to a 32-byte big-endian array
func (r *FieldElement) getB32(b32 []byte) {
	if len(b32) != 32 {
		panic("output buffer must be 32 bytes")
	}

	if !r.normalized {
		panic("field element must be normalized")
	}

	// Convert from limbs to big-endian bytes
	writeBE64(b32[0:8], (r.n[4]<<16)|(r.n[3]>>36))
	writeBE64(b32[8:16], (r.n[3]<<28)|(r.n[2]>>24))
	writeBE64(b32[16:24], (r.n[2]<<40)|(r.n[1]>>12))
	writeBE64(b32[24:32], (r.n[1]<<52)|r.n[0])
}

// normalize normalizes a field element to have magnitude 1 and be fully reduced
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
	mask := uint64(-flag)
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
	if !r.normalized {
		panic("field element must be normalized")
	}

	// Convert from 5x52 to 4x64 representation
	s.n[0] = r.n[0] | (r.n[1] << 52)
	s.n[1] = (r.n[1] >> 12) | (r.n[2] << 40)
	s.n[2] = (r.n[2] >> 24) | (r.n[3] << 28)
	s.n[3] = (r.n[3] >> 36) | (r.n[4] << 16)
}

// fromStorage converts from storage format to field element
func (r *FieldElement) fromStorage(s *FieldElementStorage) {
	// Convert from 4x64 to 5x52 representation
	r.n[0] = s.n[0] & limb0Max
	r.n[1] = ((s.n[0] >> 52) | (s.n[1] << 12)) & limb0Max
	r.n[2] = ((s.n[1] >> 40) | (s.n[2] << 24)) & limb0Max
	r.n[3] = ((s.n[2] >> 28) | (s.n[3] << 36)) & limb0Max
	r.n[4] = s.n[3] >> 16

	r.magnitude = 1
	r.normalized = true
}

// Helper function for conditional assignment
func conditionalInt(cond bool, a, b int) int {
	if cond {
		return a
	}
	return b
}
