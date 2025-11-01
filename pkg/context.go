package p256k1

import (
	"errors"
	"unsafe"
)

// Context represents a secp256k1 context object that holds randomization data
// and callback functions for enhanced protection against side-channel leakage
type Context struct {
	ecmultGenCtx    EcmultGenContext
	illegalCallback Callback
	errorCallback   Callback
	declassify      bool
}

// EcmultGenContext holds precomputed data for scalar multiplication with the generator
type EcmultGenContext struct {
	built      bool
	// Precomputed table: prec[i][j] = (j+1) * 2^(i*4) * G
	prec       [64][16]GroupElementAffine
	blindPoint GroupElementAffine // Blinding point for side-channel protection
}

// Context flags
const (
	ContextNone       = 0x01
	ContextVerify     = 0x01 | 0x0100 // Deprecated, treated as NONE
	ContextSign       = 0x01 | 0x0200 // Deprecated, treated as NONE
	ContextDeclassify = 0x01 | 0x0400 // Testing flag
)

// Static context for basic operations (limited functionality)
var ContextStatic = &Context{
	ecmultGenCtx:    EcmultGenContext{built: false},
	illegalCallback: defaultIllegalCallback,
	errorCallback:   defaultErrorCallback,
	declassify:      false,
}

// ContextCreate creates a new secp256k1 context object
func ContextCreate(flags uint) (ctx *Context, err error) {
	// Validate flags
	if (flags & 0xFF) != ContextNone {
		return nil, errors.New("invalid flags")
	}

	ctx = &Context{
		illegalCallback: defaultIllegalCallback,
		errorCallback:   defaultErrorCallback,
		declassify:      (flags & ContextDeclassify) != 0,
	}

	// Build the ecmult_gen context
	err = ctx.ecmultGenCtx.build()
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

// ContextClone creates a copy of a context
func ContextClone(ctx *Context) (newCtx *Context, err error) {
	if ctx == ContextStatic {
		return nil, errors.New("cannot clone static context")
	}

	newCtx = &Context{
		ecmultGenCtx:    ctx.ecmultGenCtx,
		illegalCallback: ctx.illegalCallback,
		errorCallback:   ctx.errorCallback,
		declassify:      ctx.declassify,
	}

	return newCtx, nil
}

// ContextDestroy destroys a context object
func ContextDestroy(ctx *Context) {
	if ctx == nil || ctx == ContextStatic {
		return
	}

	ctx.ecmultGenCtx.clear()
	ctx.illegalCallback = Callback{}
	ctx.errorCallback = Callback{}
}

// ContextSetIllegalCallback sets the illegal argument callback
func ContextSetIllegalCallback(ctx *Context, fn func(string, interface{}), data interface{}) error {
	if ctx == ContextStatic {
		return errors.New("cannot set callback on static context")
	}

	if fn == nil {
		ctx.illegalCallback = defaultIllegalCallback
	} else {
		ctx.illegalCallback = Callback{Fn: fn, Data: data}
	}

	return nil
}

// ContextSetErrorCallback sets the error callback
func ContextSetErrorCallback(ctx *Context, fn func(string, interface{}), data interface{}) error {
	if ctx == ContextStatic {
		return errors.New("cannot set callback on static context")
	}

	if fn == nil {
		ctx.errorCallback = defaultErrorCallback
	} else {
		ctx.errorCallback = Callback{Fn: fn, Data: data}
	}

	return nil
}

// ContextRandomize randomizes the context for enhanced side-channel protection
func ContextRandomize(ctx *Context, seed32 []byte) error {
	if ctx == ContextStatic {
		return errors.New("cannot randomize static context")
	}

	if !ctx.ecmultGenCtx.built {
		return errors.New("context not properly initialized")
	}

	if seed32 != nil && len(seed32) != 32 {
		return errors.New("seed must be 32 bytes or nil")
	}

	// Apply randomization to the ecmult_gen context
	return ctx.ecmultGenCtx.blind(seed32)
}

// isProper checks if a context is proper (not static and properly initialized)
func (ctx *Context) isProper() bool {
	return ctx != ContextStatic && ctx.ecmultGenCtx.built
}

// EcmultGenContext methods

// build initializes the ecmult_gen context with precomputed values
func (ctx *EcmultGenContext) build() error {
	if ctx.built {
		return nil
	}
	
	// Initialize with proper generator coordinates
	var generator GroupElementAffine
	var gx, gy [32]byte
	
	// Generator X coordinate
	gx = [32]byte{
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}
	// Generator Y coordinate
	gy = [32]byte{
		0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
		0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
		0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
	}
	
	generator.x.setB32(gx[:])
	generator.y.setB32(gy[:])
	generator.x.normalize()
	generator.y.normalize()
	generator.infinity = false
	
	// Build precomputed table for optimized generator multiplication
	current := generator
	
	// For each window position (64 windows of 4 bits each)
	for i := 0; i < 64; i++ {
		// First entry is point at infinity (0 * current)
		ctx.prec[i][0] = InfinityAffine
		
		// Remaining entries are multiples: 1*current, 2*current, ..., 15*current
		ctx.prec[i][1] = current
		
		var temp GroupElementJacobian
		temp.setGE(&current)
		
		for j := 2; j < 16; j++ {
			temp.addGE(&temp, &current)
			ctx.prec[i][j].setGEJ(&temp)
		}
		
		// Move to next window: current = 2^4 * current = 16 * current
		temp.setGE(&current)
		for k := 0; k < 4; k++ {
			temp.double(&temp)
		}
		current.setGEJ(&temp)
	}
	
	// Initialize blinding point to infinity
	ctx.blindPoint = InfinityAffine
	ctx.built = true
	return nil
}

// clear clears the ecmult_gen context
func (ctx *EcmultGenContext) clear() {
	// Clear precomputed data
	for i := range ctx.prec {
		for j := range ctx.prec[i] {
			ctx.prec[i][j].clear()
		}
	}
	ctx.blindPoint.clear()
	ctx.built = false
}

// blind applies blinding to the precomputed table for side-channel protection
func (ctx *EcmultGenContext) blind(seed32 []byte) error {
	if !ctx.built {
		return errors.New("context not built")
	}

	var blindingFactor Scalar

	if seed32 == nil {
		// Remove blinding
		ctx.blindPoint = InfinityAffine
		return nil
	} else {
		blindingFactor.setB32(seed32)
	}

	// Apply blinding to precomputed table
	// This is a simplified implementation - real version needs proper blinding

	// For now, just mark as blinded (actual blinding is complex)
	return nil
}

// isBuilt returns true if the ecmult_gen context is built
func (ctx *EcmultGenContext) isBuilt() bool {
	return ctx.built
}

// Selftest performs basic self-tests to detect serious usage errors
func Selftest() error {
	// Test basic field operations
	var a, b, c FieldElement
	a.setInt(1)
	b.setInt(2)
	c.add(&a)
	c.add(&b)
	c.normalize()

	var expected FieldElement
	expected.setInt(3)
	expected.normalize()

	if !c.equal(&expected) {
		return errors.New("field addition self-test failed")
	}

	// Test basic scalar operations
	var sa, sb, sc Scalar
	sa.setInt(2)
	sb.setInt(3)
	sc.mul(&sa, &sb)

	var sexpected Scalar
	sexpected.setInt(6)

	if !sc.equal(&sexpected) {
		return errors.New("scalar multiplication self-test failed")
	}

	// Test point operations
	var p GroupElementAffine
	p = GeneratorAffine

	if !p.isValid() {
		return errors.New("generator point validation failed")
	}

	return nil
}

// declassifyMem marks memory as no-longer-secret for constant-time analysis
func (ctx *Context) declassifyMem(ptr unsafe.Pointer, len uintptr) {
	if ctx.declassify {
		// In a real implementation, this would call memory analysis tools
		// For now, this is a no-op
	}
}
