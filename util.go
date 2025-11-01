// Package p256k1 provides a pure Go implementation of the secp256k1 elliptic curve
// cryptographic primitives, ported from the libsecp256k1 C library.
package p256k1

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"
)

// Constants from the C implementation
const (
	// Field prime: 2^256 - 2^32 - 977
	FieldPrime = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

	// Group order (number of points on the curve)
	GroupOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
)

// Utility functions ported from util.h

// memclear clears memory to prevent leaking sensitive information
func memclear(ptr unsafe.Pointer, n uintptr) {
	// Zero the memory
	slice := (*[1 << 30]byte)(ptr)[:n:n]
	for i := range slice {
		slice[i] = 0
	}
}

// memczero conditionally zeros memory if flag == 1. Flag must be 0 or 1. Constant time.
func memczero(s []byte, flag int) {
	mask := byte(-flag)
	for i := range s {
		s[i] &= ^mask
	}
}

// isZeroArray returns 1 if all elements of array s are 0, otherwise 0. Constant-time.
func isZeroArray(s []byte) (ret int) {
	var acc byte
	for i := range s {
		acc |= s[i]
	}
	ret = subtle.ConstantTimeByteEq(acc, 0)
	return
}

// intCmov conditionally moves an integer. If flag is true, set *r equal to *a; otherwise leave it.
// Constant-time. Both *r and *a must be initialized and non-negative.
func intCmov(r *int, a *int, flag int) {
	*r = subtle.ConstantTimeSelect(flag, *a, *r)
}

// readBE32 reads a uint32 in big endian
func readBE32(p []byte) uint32 {
	return binary.BigEndian.Uint32(p)
}

// writeBE32 writes a uint32 in big endian
func writeBE32(p []byte, x uint32) {
	binary.BigEndian.PutUint32(p, x)
}

// readBE64 reads a uint64 in big endian
func readBE64(p []byte) uint64 {
	return binary.BigEndian.Uint64(p)
}

// writeBE64 writes a uint64 in big endian
func writeBE64(p []byte, x uint64) {
	binary.BigEndian.PutUint64(p, x)
}

// rotr32 rotates a uint32 to the right
func rotr32(x uint32, by uint) uint32 {
	by &= 31 // Reduce rotation amount to avoid issues
	return (x >> by) | (x << (32 - by))
}

// ctz32Var determines the number of trailing zero bits in a (non-zero) 32-bit x
func ctz32Var(x uint32) int {
	if x == 0 {
		panic("ctz32Var called with zero")
	}

	// Use De Bruijn sequence for bit scanning
	debruijn := [32]uint8{
		0x00, 0x01, 0x02, 0x18, 0x03, 0x13, 0x06, 0x19, 0x16, 0x04, 0x14, 0x0A,
		0x10, 0x07, 0x0C, 0x1A, 0x1F, 0x17, 0x12, 0x05, 0x15, 0x09, 0x0F, 0x0B,
		0x1E, 0x11, 0x08, 0x0E, 0x1D, 0x0D, 0x1C, 0x1B,
	}
	return int(debruijn[(x&-x)*0x04D7651F>>27])
}

// ctz64Var determines the number of trailing zero bits in a (non-zero) 64-bit x
func ctz64Var(x uint64) int {
	if x == 0 {
		panic("ctz64Var called with zero")
	}

	// Use De Bruijn sequence for bit scanning
	debruijn := [64]uint8{
		0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
		62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
		63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
		51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12,
	}
	return int(debruijn[(x&-x)*0x022FDD63CC95386D>>58])
}

// Callback represents an error callback function
type Callback struct {
	Fn   func(string, interface{})
	Data interface{}
}

// call invokes the callback function
func (cb *Callback) call(text string) {
	if cb.Fn != nil {
		cb.Fn(text, cb.Data)
	}
}

// Default callbacks
var (
	defaultIllegalCallback = Callback{
		Fn: func(str string, data interface{}) {
			fmt.Fprintf(os.Stderr, "[libsecp256k1] illegal argument: %s\n", str)
			os.Exit(1)
		},
	}

	defaultErrorCallback = Callback{
		Fn: func(str string, data interface{}) {
			fmt.Fprintf(os.Stderr, "[libsecp256k1] internal consistency check failed: %s\n", str)
			os.Exit(1)
		},
	}
)

// argCheck checks a condition and calls the illegal callback if it fails
func argCheck(cond bool, ctx *Context, msg string) (ok bool) {
	if !cond {
		if ctx != nil {
			ctx.illegalCallback.call(msg)
		} else {
			defaultIllegalCallback.call(msg)
		}
		return false
	}
	return true
}

// verifyCheck checks a condition in verify mode (debug builds)
func verifyCheck(cond bool, msg string) {
	if !cond {
		defaultErrorCallback.call(msg)
	}
}
