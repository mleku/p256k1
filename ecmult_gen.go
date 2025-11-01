package p256k1

import (
	"sync"
)

const (
	// Number of bytes in a 256-bit scalar
	numBytes = 32
	// Number of possible byte values
	numByteValues = 256
)

// bytePointTable stores precomputed byte points for each byte position
// bytePoints[byteNum][byteVal] = byteVal * 2^(8*(31-byteNum)) * G
// where byteNum is 0-31 (MSB to LSB) and byteVal is 0-255
// Each entry stores [X, Y] coordinates as 32-byte arrays
type bytePointTable [numBytes][numByteValues][2][32]byte

// EcmultGenContext holds precomputed data for generator multiplication
type EcmultGenContext struct {
	// Precomputed byte points: bytePoints[byteNum][byteVal] = [X, Y] coordinates
	// in affine form for byteVal * 2^(8*(31-byteNum)) * G
	bytePoints  bytePointTable
	initialized bool
}

var (
	// Global context for generator multiplication (initialized once)
	globalGenContext *EcmultGenContext
	genContextOnce   sync.Once
)

// initGenContext initializes the precomputed byte points table
func (ctx *EcmultGenContext) initGenContext() {
	// Start with G (generator point)
	var gJac GroupElementJacobian
	gJac.setGE(&Generator)

	// Compute base points for each byte position
	// For byteNum i, we need: byteVal * 2^(8*(31-i)) * G
	// We'll compute each byte position's base multiplier first

	// Compute 2^8 * G, 2^16 * G, ..., 2^248 * G
	var byteBases [numBytes]GroupElementJacobian

	// Base for byte 31 (LSB): 2^0 * G = G
	byteBases[31] = gJac

	// Compute bases for bytes 30 down to 0 (MSB)
	// byteBases[i] = 2^(8*(31-i)) * G
	for i := numBytes - 2; i >= 0; i-- {
		// byteBases[i] = byteBases[i+1] * 2^8
		byteBases[i] = byteBases[i+1]
		for j := 0; j < 8; j++ {
			byteBases[i].double(&byteBases[i])
		}
	}

	// Now compute all byte points for each byte position
	for byteNum := 0; byteNum < numBytes; byteNum++ {
		base := byteBases[byteNum]

		// Convert base to affine for efficiency
		var baseAff GroupElementAffine
		baseAff.setGEJ(&base)

		// bytePoints[byteNum][0] = infinity (point at infinity)
		// We'll skip this and handle it in the lookup

		// bytePoints[byteNum][1] = base
		var ptJac GroupElementJacobian
		ptJac.setGE(&baseAff)
		var ptAff GroupElementAffine
		ptAff.setGEJ(&ptJac)
		ptAff.x.normalize()
		ptAff.y.normalize()
		ptAff.x.getB32(ctx.bytePoints[byteNum][1][0][:])
		ptAff.y.getB32(ctx.bytePoints[byteNum][1][1][:])

		// Compute bytePoints[byteNum][byteVal] = byteVal * base
		// We'll use addition to build up multiples
		var accJac GroupElementJacobian = ptJac
		var accAff GroupElementAffine

		for byteVal := 2; byteVal < numByteValues; byteVal++ {
			// acc = acc + base
			accJac.addVar(&accJac, &ptJac)
			accAff.setGEJ(&accJac)
			accAff.x.normalize()
			accAff.y.normalize()
			accAff.x.getB32(ctx.bytePoints[byteNum][byteVal][0][:])
			accAff.y.getB32(ctx.bytePoints[byteNum][byteVal][1][:])
		}
	}

	ctx.initialized = true
}

// getGlobalGenContext returns the global precomputed context
func getGlobalGenContext() *EcmultGenContext {
	genContextOnce.Do(func() {
		globalGenContext = &EcmultGenContext{}
		globalGenContext.initGenContext()
	})
	return globalGenContext
}

// NewEcmultGenContext creates a new generator multiplication context
func NewEcmultGenContext() *EcmultGenContext {
	ctx := &EcmultGenContext{}
	ctx.initGenContext()
	return ctx
}

// ecmultGen computes r = n * G where G is the generator point
// Uses 8-bit byte-based lookup table (like btcec) for maximum efficiency
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

	// Byte-based method: process one byte at a time (MSB to LSB)
	// For each byte, lookup the precomputed point and add it
	r.setInfinity()

	// Get scalar bytes (MSB to LSB)
	var scalarBytes [32]byte
	n.getB32(scalarBytes[:])

	for byteNum := 0; byteNum < numBytes; byteNum++ {
		byteVal := scalarBytes[byteNum]

		// Skip zero bytes
		if byteVal == 0 {
			continue
		}

		// Lookup precomputed point for this byte
		var ptAff GroupElementAffine
		var xFe, yFe FieldElement
		xFe.setB32(ctx.bytePoints[byteNum][byteVal][0][:])
		yFe.setB32(ctx.bytePoints[byteNum][byteVal][1][:])
		ptAff.setXY(&xFe, &yFe)

		// Convert to Jacobian and add
		var ptJac GroupElementJacobian
		ptJac.setGE(&ptAff)

		if r.isInfinity() {
			*r = ptJac
		} else {
			r.addVar(r, &ptJac)
		}
	}
}

// EcmultGen is the public interface for generator multiplication
func EcmultGen(r *GroupElementJacobian, n *Scalar) {
	// Use global precomputed context for efficiency
	ctx := getGlobalGenContext()
	ctx.ecmultGen(r, n)
}
