package p256k1

// EcmultGenContext holds precomputed data for generator multiplication
type EcmultGenContext struct {
	// Precomputed odd multiples of the generator
	// This would contain precomputed tables in a real implementation
	initialized bool
}

// NewEcmultGenContext creates a new generator multiplication context
func NewEcmultGenContext() *EcmultGenContext {
	return &EcmultGenContext{
		initialized: true,
	}
}

// ecmultGen computes r = n * G where G is the generator point
// This is a simplified implementation - the real version would use precomputed tables
func (ctx *EcmultGenContext) ecmultGen(r *GroupElementJacobian, n *Scalar) {
	if !ctx.initialized {
		panic("ecmult_gen context not initialized")
	}
	
	// Handle zero scalar
	if n.isZero() {
		r.setInfinity()
		return
	}
	
	// Handle scalar = 1
	if n.isOne() {
		r.setGE(&Generator)
		return
	}
	
	// Simple binary method for now (not optimal but correct)
	// Real implementation would use precomputed tables and windowing
	r.setInfinity()
	
	var base GroupElementJacobian
	base.setGE(&Generator)
	
	// Process each bit of the scalar
	for i := 0; i < 256; i++ {
		// Double the accumulator
		if i > 0 {
			r.double(r)
		}
		
		// Extract bit i from scalar (from MSB)
		bit := n.getBits(uint(255-i), 1)
		if bit != 0 {
			if r.isInfinity() {
				*r = base
			} else {
				r.addVar(r, &base)
			}
		}
	}
}

// EcmultGen is the public interface for generator multiplication
func EcmultGen(r *GroupElementJacobian, n *Scalar) {
	// Use a default context for now
	// In a real implementation, this would use a global precomputed context
	ctx := NewEcmultGenContext()
	ctx.ecmultGen(r, n)
}
