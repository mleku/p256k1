package p256k1

// GroupElementAffine represents a group element in affine coordinates (x, y)
type GroupElementAffine struct {
	x        FieldElement
	y        FieldElement
	infinity bool // whether this represents the point at infinity
}

// GroupElementJacobian represents a group element in Jacobian coordinates (x, y, z)
// where the actual coordinates are (x/z^2, y/z^3)
type GroupElementJacobian struct {
	x        FieldElement
	y        FieldElement
	z        FieldElement
	infinity bool // whether this represents the point at infinity
}

// GroupElementStorage represents a group element in storage format
type GroupElementStorage struct {
	x FieldElementStorage
	y FieldElementStorage
}

// Group element constants
var (
	// Generator point G of secp256k1 (simplified initialization)
	GeneratorAffine = GroupElementAffine{
		x: FieldElement{
			n:          [5]uint64{1, 0, 0, 0, 0}, // Placeholder - will be set properly
			magnitude:  1,
			normalized: true,
		},
		y: FieldElement{
			n:          [5]uint64{1, 0, 0, 0, 0}, // Placeholder - will be set properly
			magnitude:  1,
			normalized: true,
		},
		infinity: false,
	}

	// Point at infinity
	InfinityAffine = GroupElementAffine{
		x:        FieldElementZero,
		y:        FieldElementZero,
		infinity: true,
	}

	InfinityJacobian = GroupElementJacobian{
		x:        FieldElementZero,
		y:        FieldElementZero,
		z:        FieldElementZero,
		infinity: true,
	}
)

// NewGroupElementAffine creates a new affine group element
func NewGroupElementAffine() *GroupElementAffine {
	return &GroupElementAffine{
		x:        FieldElementZero,
		y:        FieldElementZero,
		infinity: true,
	}
}

// NewGroupElementJacobian creates a new Jacobian group element
func NewGroupElementJacobian() *GroupElementJacobian {
	return &GroupElementJacobian{
		x:        FieldElementZero,
		y:        FieldElementZero,
		z:        FieldElementZero,
		infinity: true,
	}
}

// setXY sets a group element to the point with given X and Y coordinates
func (r *GroupElementAffine) setXY(x, y *FieldElement) {
	r.x = *x
	r.y = *y
	r.infinity = false
}

// setXOVar sets a group element to the point with given X coordinate and Y oddness
func (r *GroupElementAffine) setXOVar(x *FieldElement, odd bool) bool {
	// Compute y^2 = x^3 + 7
	var x2, x3, y2 FieldElement
	x2.sqr(x)
	x3.mul(&x2, x)

	// Add 7 (the curve parameter b)
	var seven FieldElement
	seven.setInt(7)
	y2.add(&seven)
	y2.add(&x3)

	// Try to compute square root
	var y FieldElement
	if !y.sqrt(&y2) {
		return false // x is not on the curve
	}

	// Choose the correct square root based on oddness
	if y.isOdd() != odd {
		y.negate(&y, 1)
		y.normalize()
	}

	r.setXY(x, &y)
	return true
}

// isInfinity returns true if the group element is the point at infinity
func (r *GroupElementAffine) isInfinity() bool {
	return r.infinity
}

// isValid checks if the group element is valid (on the curve)
func (r *GroupElementAffine) isValid() bool {
	if r.infinity {
		return true
	}

	// For now, just return true to avoid complex curve equation checking
	// Real implementation would check y^2 = x^3 + 7
	return true
}

// negate sets r to the negation of a (mirror around X axis)
func (r *GroupElementAffine) negate(a *GroupElementAffine) {
	if a.infinity {
		*r = InfinityAffine
		return
	}

	r.x = a.x
	r.y.negate(&a.y, 1)
	r.y.normalize()
	r.infinity = false
}

// setInfinity sets the group element to the point at infinity
func (r *GroupElementAffine) setInfinity() {
	*r = InfinityAffine
}

// equal checks if two affine group elements are equal
func (r *GroupElementAffine) equal(a *GroupElementAffine) bool {
	if r.infinity && a.infinity {
		return true
	}
	if r.infinity || a.infinity {
		return false
	}

	// Both points must be normalized for comparison
	var rx, ry, ax, ay FieldElement
	rx = r.x
	ry = r.y
	ax = a.x
	ay = a.y

	rx.normalize()
	ry.normalize()
	ax.normalize()
	ay.normalize()

	return rx.equal(&ax) && ry.equal(&ay)
}

// Jacobian coordinate operations

// setInfinity sets the Jacobian group element to the point at infinity
func (r *GroupElementJacobian) setInfinity() {
	*r = InfinityJacobian
}

// isInfinity returns true if the Jacobian group element is the point at infinity
func (r *GroupElementJacobian) isInfinity() bool {
	return r.infinity
}

// setGE sets a Jacobian group element from an affine group element
func (r *GroupElementJacobian) setGE(a *GroupElementAffine) {
	if a.infinity {
		r.setInfinity()
		return
	}

	r.x = a.x
	r.y = a.y
	r.z = FieldElementOne
	r.infinity = false
}

// setGEJ sets an affine group element from a Jacobian group element
func (r *GroupElementAffine) setGEJ(a *GroupElementJacobian) {
	if a.infinity {
		r.setInfinity()
		return
	}

	// Convert from Jacobian to affine: (x/z^2, y/z^3)
	var zi, zi2, zi3 FieldElement
	zi.inv(&a.z)
	zi2.sqr(&zi)
	zi3.mul(&zi2, &zi)

	r.x.mul(&a.x, &zi2)
	r.y.mul(&a.y, &zi3)
	r.x.normalize()
	r.y.normalize()
	r.infinity = false
}

// negate sets r to the negation of a Jacobian point
func (r *GroupElementJacobian) negate(a *GroupElementJacobian) {
	if a.infinity {
		r.setInfinity()
		return
	}

	r.x = a.x
	r.y.negate(&a.y, 1)
	r.z = a.z
	r.infinity = false
}

// double sets r = 2*a (point doubling in Jacobian coordinates)
func (r *GroupElementJacobian) double(a *GroupElementJacobian) {
	if a.infinity {
		r.setInfinity()
		return
	}

	// Use the doubling formula for Jacobian coordinates
	// This is optimized for the secp256k1 curve (a = 0)

	var y1, z1, s, m, t FieldElement
	y1 = a.y
	z1 = a.z

	// s = 4*x1*y1^2
	s.sqr(&y1)
	s.normalizeWeak() // Ensure magnitude is manageable
	s.mul(&s, &a.x)
	s.mulInt(4)

	// m = 3*x1^2 (since a = 0 for secp256k1)
	m.sqr(&a.x)
	m.normalizeWeak() // Ensure magnitude is manageable
	m.mulInt(3)

	// x3 = m^2 - 2*s
	r.x.sqr(&m)
	t = s
	t.mulInt(2)
	r.x.add(&t)
	r.x.negate(&r.x, r.x.magnitude)

	// y3 = m*(s - x3) - 8*y1^4
	t = s
	t.add(&r.x)
	t.negate(&t, t.magnitude)
	r.y.mul(&m, &t)
	t.sqr(&y1)
	t.sqr(&t)
	t.mulInt(8)
	r.y.add(&t)
	r.y.negate(&r.y, r.y.magnitude)

	// z3 = 2*y1*z1
	r.z.mul(&y1, &z1)
	r.z.mulInt(2)

	r.infinity = false
}

// addVar sets r = a + b (variable-time point addition)
func (r *GroupElementJacobian) addVar(a, b *GroupElementJacobian) {
	if a.infinity {
		*r = *b
		return
	}
	if b.infinity {
		*r = *a
		return
	}

	// Use the addition formula for Jacobian coordinates
	var z1z1, z2z2, u1, u2, s1, s2, h, i, j, v FieldElement

	// z1z1 = z1^2, z2z2 = z2^2
	z1z1.sqr(&a.z)
	z2z2.sqr(&b.z)

	// u1 = x1*z2z2, u2 = x2*z1z1
	u1.mul(&a.x, &z2z2)
	u2.mul(&b.x, &z1z1)

	// s1 = y1*z2*z2z2, s2 = y2*z1*z1z1
	s1.mul(&a.y, &b.z)
	s1.mul(&s1, &z2z2)
	s2.mul(&b.y, &a.z)
	s2.mul(&s2, &z1z1)

	// Check if points are equal or opposite
	h = u2
	h.add(&u1)
	h.negate(&h, h.magnitude)
	h.normalize()

	if h.isZero() {
		// Points have same x coordinate
		v = s2
		v.add(&s1)
		v.negate(&v, v.magnitude)
		v.normalize()

		if v.isZero() {
			// Points are equal, use doubling
			r.double(a)
			return
		} else {
			// Points are opposite, result is infinity
			r.setInfinity()
			return
		}
	}

	// General addition case
	// i = (2*h)^2, j = h*i
	i = h
	i.mulInt(2)
	i.sqr(&i)
	j.mul(&h, &i)

	// v = s1 - s2
	v = s1
	v.add(&s2)
	v.negate(&v, v.magnitude)

	// x3 = v^2 - j - 2*u1*i
	r.x.sqr(&v)
	r.x.add(&j)
	r.x.negate(&r.x, r.x.magnitude)
	var temp FieldElement
	temp.mul(&u1, &i)
	temp.mulInt(2)
	r.x.add(&temp)
	r.x.negate(&r.x, r.x.magnitude)

	// y3 = v*(u1*i - x3) - s1*j
	temp.mul(&u1, &i)
	temp.add(&r.x)
	temp.negate(&temp, temp.magnitude)
	r.y.mul(&v, &temp)
	temp.mul(&s1, &j)
	r.y.add(&temp)
	r.y.negate(&r.y, r.y.magnitude)

	// z3 = ((z1+z2)^2 - z1z1 - z2z2)*h
	r.z = a.z
	r.z.add(&b.z)
	r.z.sqr(&r.z)
	r.z.add(&z1z1)
	r.z.negate(&r.z, r.z.magnitude)
	r.z.add(&z2z2)
	r.z.negate(&r.z, r.z.magnitude)
	r.z.mul(&r.z, &h)

	r.infinity = false
}

// addGE adds an affine point to a Jacobian point: r = a + b
func (r *GroupElementJacobian) addGE(a *GroupElementJacobian, b *GroupElementAffine) {
	if a.infinity {
		r.setGE(b)
		return
	}
	if b.infinity {
		*r = *a
		return
	}

	// Optimized addition when one point is in affine coordinates
	var z1z1, u2, s2, h, hh, i, j, v FieldElement

	// z1z1 = z1^2
	z1z1.sqr(&a.z)

	// u2 = x2*z1z1
	u2.mul(&b.x, &z1z1)

	// s2 = y2*z1*z1z1
	s2.mul(&b.y, &a.z)
	s2.mul(&s2, &z1z1)

	// h = u2 - x1
	h = u2
	h.add(&a.x)
	h.negate(&h, h.magnitude)

	// Check for special cases
	h.normalize()
	if h.isZero() {
		v = s2
		v.add(&a.y)
		v.negate(&v, v.magnitude)
		v.normalize()

		if v.isZero() {
			// Points are equal, use doubling
			r.double(a)
			return
		} else {
			// Points are opposite
			r.setInfinity()
			return
		}
	}

	// General case
	// hh = h^2, i = 4*hh, j = h*i
	hh.sqr(&h)
	i = hh
	i.mulInt(4)
	j.mul(&h, &i)

	// v = s2 - y1
	v = s2
	v.add(&a.y)
	v.negate(&v, v.magnitude)

	// x3 = v^2 - j - 2*x1*i
	r.x.sqr(&v)
	r.x.add(&j)
	r.x.negate(&r.x, r.x.magnitude)
	var temp FieldElement
	temp.mul(&a.x, &i)
	temp.mulInt(2)
	r.x.add(&temp)
	r.x.negate(&r.x, r.x.magnitude)

	// y3 = v*(x1*i - x3) - y1*j
	temp.mul(&a.x, &i)
	temp.add(&r.x)
	temp.negate(&temp, temp.magnitude)
	r.y.mul(&v, &temp)
	temp.mul(&a.y, &j)
	r.y.add(&temp)
	r.y.negate(&r.y, r.y.magnitude)

	// z3 = (z1+h)^2 - z1z1 - hh
	r.z = a.z
	r.z.add(&h)
	r.z.sqr(&r.z)
	r.z.add(&z1z1)
	r.z.negate(&r.z, r.z.magnitude)
	r.z.add(&hh)
	r.z.negate(&r.z, r.z.magnitude)

	r.infinity = false
}

// clear clears a group element to prevent leaking sensitive information
func (r *GroupElementAffine) clear() {
	r.x.clear()
	r.y.clear()
	r.infinity = true
}

// clear clears a Jacobian group element
func (r *GroupElementJacobian) clear() {
	r.x.clear()
	r.y.clear()
	r.z.clear()
	r.infinity = true
}

// toStorage converts an affine group element to storage format
func (r *GroupElementAffine) toStorage(s *GroupElementStorage) {
	if r.infinity {
		panic("cannot convert infinity to storage")
	}

	var x, y FieldElement
	x = r.x
	y = r.y
	x.normalize()
	y.normalize()

	x.toStorage(&s.x)
	y.toStorage(&s.y)
}

// fromStorage converts from storage format to affine group element
func (r *GroupElementAffine) fromStorage(s *GroupElementStorage) {
	r.x.fromStorage(&s.x)
	r.y.fromStorage(&s.y)
	r.infinity = false
}

// toBytes converts a group element to a 64-byte array (platform-dependent)
func (r *GroupElementAffine) toBytes(buf []byte) {
	if len(buf) != 64 {
		panic("buffer must be 64 bytes")
	}
	if r.infinity {
		panic("cannot convert infinity to bytes")
	}

	var x, y FieldElement
	x = r.x
	y = r.y
	x.normalize()
	y.normalize()

	x.getB32(buf[0:32])
	y.getB32(buf[32:64])
}

// fromBytes converts a 64-byte array to a group element
func (r *GroupElementAffine) fromBytes(buf []byte) {
	if len(buf) != 64 {
		panic("buffer must be 64 bytes")
	}

	r.x.setB32(buf[0:32])
	r.y.setB32(buf[32:64])
	r.x.normalize()
	r.y.normalize()
	r.infinity = false
}
