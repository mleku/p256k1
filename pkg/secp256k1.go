package p256k1

// PublicKey represents a parsed and valid public key (64 bytes)
type PublicKey struct {
	data [64]byte
}

// Signature represents a parsed ECDSA signature (64 bytes)
type Signature struct {
	data [64]byte
}

// Compression flags for public key serialization
const (
	ECCompressed   = 0x0102
	ECUncompressed = 0x0002
)

// Tag bytes for various encoded curve points
const (
	TagPubkeyEven         = 0x02
	TagPubkeyOdd          = 0x03
	TagPubkeyUncompressed = 0x04
	TagPubkeyHybridEven   = 0x06
	TagPubkeyHybridOdd    = 0x07
)

// Nonce generation function type
type NonceFunction func(nonce32 []byte, msg32 []byte, key32 []byte, algo16 []byte, data interface{}, attempt uint) bool

// Default nonce function (RFC 6979)
var NonceFunction6979 NonceFunction = rfc6979NonceFunction
var NonceFunctionDefault NonceFunction = rfc6979NonceFunction

// ECPubkeyParse parses a variable-length public key into the pubkey object
func ECPubkeyParse(ctx *Context, pubkey *PublicKey, input []byte) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(pubkey != nil, ctx, "pubkey != NULL") {
		return false
	}
	if !argCheck(input != nil, ctx, "input != NULL") {
		return false
	}

	// Clear the pubkey first
	for i := range pubkey.data {
		pubkey.data[i] = 0
	}

	var point GroupElementAffine
	if !ecKeyPubkeyParse(&point, input) {
		return false
	}

	if !point.isValid() {
		return false
	}

	pubkeySave(pubkey, &point)
	return true
}

// ECPubkeySerialize serializes a pubkey object into a byte sequence
func ECPubkeySerialize(ctx *Context, output []byte, outputlen *int, pubkey *PublicKey, flags uint) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(outputlen != nil, ctx, "outputlen != NULL") {
		return false
	}

	compressed := (flags & ECCompressed) != 0
	expectedLen := 33
	if !compressed {
		expectedLen = 65
	}

	if !argCheck(*outputlen >= expectedLen, ctx, "output buffer too small") {
		return false
	}
	if !argCheck(output != nil, ctx, "output != NULL") {
		return false
	}
	if !argCheck(pubkey != nil, ctx, "pubkey != NULL") {
		return false
	}
	if !argCheck((flags&0xFF) == 0x02, ctx, "invalid flags") {
		return false
	}

	var point GroupElementAffine
	if !pubkeyLoad(&point, pubkey) {
		return false
	}

	actualLen := ecKeyPubkeySerialize(&point, output, compressed)
	if actualLen == 0 {
		return false
	}

	*outputlen = actualLen
	return true
}

// ECPubkeyCmp compares two public keys using lexicographic order
func ECPubkeyCmp(ctx *Context, pubkey1, pubkey2 *PublicKey) (result int) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return 0
	}
	if !argCheck(pubkey1 != nil, ctx, "pubkey1 != NULL") {
		return 0
	}
	if !argCheck(pubkey2 != nil, ctx, "pubkey2 != NULL") {
		return 0
	}

	var out1, out2 [33]byte
	var len1, len2 int = 33, 33

	// Serialize both keys in compressed format for comparison
	ECPubkeySerialize(ctx, out1[:], &len1, pubkey1, ECCompressed)
	ECPubkeySerialize(ctx, out2[:], &len2, pubkey2, ECCompressed)

	// Compare the serialized forms
	for i := 0; i < 33; i++ {
		if out1[i] < out2[i] {
			return -1
		}
		if out1[i] > out2[i] {
			return 1
		}
	}
	return 0
}

// ECDSASignatureParseDER parses a DER ECDSA signature
func ECDSASignatureParseDER(ctx *Context, sig *Signature, input []byte) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(sig != nil, ctx, "sig != NULL") {
		return false
	}
	if !argCheck(input != nil, ctx, "input != NULL") {
		return false
	}

	var r, s Scalar
	if !ecdsaSigParse(&r, &s, input) {
		// Clear signature on failure
		for i := range sig.data {
			sig.data[i] = 0
		}
		return false
	}

	ecdsaSignatureSave(sig, &r, &s)
	return true
}

// ECDSASignatureParseCompact parses an ECDSA signature in compact (64 byte) format
func ECDSASignatureParseCompact(ctx *Context, sig *Signature, input64 []byte) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(sig != nil, ctx, "sig != NULL") {
		return false
	}
	if !argCheck(input64 != nil, ctx, "input64 != NULL") {
		return false
	}
	if !argCheck(len(input64) == 64, ctx, "input64 must be 64 bytes") {
		return false
	}

	var r, s Scalar
	overflow := false

	overflow = r.setB32(input64[0:32])
	if overflow {
		for i := range sig.data {
			sig.data[i] = 0
		}
		return false
	}

	overflow = s.setB32(input64[32:64])
	if overflow {
		for i := range sig.data {
			sig.data[i] = 0
		}
		return false
	}

	ecdsaSignatureSave(sig, &r, &s)
	return true
}

// ECDSASignatureSerializeDER serializes an ECDSA signature in DER format
func ECDSASignatureSerializeDER(ctx *Context, output []byte, outputlen *int, sig *Signature) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(output != nil, ctx, "output != NULL") {
		return false
	}
	if !argCheck(outputlen != nil, ctx, "outputlen != NULL") {
		return false
	}
	if !argCheck(sig != nil, ctx, "sig != NULL") {
		return false
	}

	var r, s Scalar
	ecdsaSignatureLoad(&r, &s, sig)

	return ecdsaSigSerialize(output, outputlen, &r, &s)
}

// ECDSASignatureSerializeCompact serializes an ECDSA signature in compact format
func ECDSASignatureSerializeCompact(ctx *Context, output64 []byte, sig *Signature) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(output64 != nil, ctx, "output64 != NULL") {
		return false
	}
	if !argCheck(len(output64) == 64, ctx, "output64 must be 64 bytes") {
		return false
	}
	if !argCheck(sig != nil, ctx, "sig != NULL") {
		return false
	}

	var r, s Scalar
	ecdsaSignatureLoad(&r, &s, sig)

	r.getB32(output64[0:32])
	s.getB32(output64[32:64])

	return true
}

// ECDSAVerify verifies an ECDSA signature
func ECDSAVerify(ctx *Context, sig *Signature, msghash32 []byte, pubkey *PublicKey) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(msghash32 != nil, ctx, "msghash32 != NULL") {
		return false
	}
	if !argCheck(len(msghash32) == 32, ctx, "msghash32 must be 32 bytes") {
		return false
	}
	if !argCheck(sig != nil, ctx, "sig != NULL") {
		return false
	}
	if !argCheck(pubkey != nil, ctx, "pubkey != NULL") {
		return false
	}

	var r, s, m Scalar
	var q GroupElementAffine

	m.setB32(msghash32)
	ecdsaSignatureLoad(&r, &s, sig)

	if !pubkeyLoad(&q, pubkey) {
		return false
	}

	// Check that s is not high (for malleability protection)
	if s.isHigh() {
		return false
	}

	return ecdsaSigVerify(&r, &s, &q, &m)
}

// ECDSASign creates an ECDSA signature
func ECDSASign(ctx *Context, sig *Signature, msghash32 []byte, seckey []byte, noncefp NonceFunction, ndata interface{}) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(ctx.ecmultGenCtx.isBuilt(), ctx, "context not built for signing") {
		return false
	}
	if !argCheck(msghash32 != nil, ctx, "msghash32 != NULL") {
		return false
	}
	if !argCheck(len(msghash32) == 32, ctx, "msghash32 must be 32 bytes") {
		return false
	}
	if !argCheck(sig != nil, ctx, "sig != NULL") {
		return false
	}
	if !argCheck(seckey != nil, ctx, "seckey != NULL") {
		return false
	}
	if !argCheck(len(seckey) == 32, ctx, "seckey must be 32 bytes") {
		return false
	}

	var r, s Scalar
	if !ecdsaSignInner(ctx, &r, &s, nil, msghash32, seckey, noncefp, ndata) {
		return false
	}

	ecdsaSignatureSave(sig, &r, &s)
	return true
}

// ECSecKeyVerify verifies that a secret key is valid
func ECSecKeyVerify(ctx *Context, seckey []byte) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(seckey != nil, ctx, "seckey != NULL") {
		return false
	}
	if !argCheck(len(seckey) == 32, ctx, "seckey must be 32 bytes") {
		return false
	}

	var sec Scalar
	return sec.setB32Seckey(seckey)
}

// ECPubkeyCreate computes the public key for a secret key
func ECPubkeyCreate(ctx *Context, pubkey *PublicKey, seckey []byte) (ok bool) {
	if !argCheck(ctx != nil, ctx, "ctx != NULL") {
		return false
	}
	if !argCheck(pubkey != nil, ctx, "pubkey != NULL") {
		return false
	}
	if !argCheck(seckey != nil, ctx, "seckey != NULL") {
		return false
	}
	if !argCheck(len(seckey) == 32, ctx, "seckey must be 32 bytes") {
		return false
	}
	if !argCheck(ctx.ecmultGenCtx.isBuilt(), ctx, "context not built for key generation") {
		return false
	}

	// Clear pubkey first
	for i := range pubkey.data {
		pubkey.data[i] = 0
	}

	var point GroupElementAffine
	var seckeyScalar Scalar

	if !ecPubkeyCreateHelper(&ctx.ecmultGenCtx, &seckeyScalar, &point, seckey) {
		return false
	}

	pubkeySave(pubkey, &point)
	return true
}

// Helper functions

// pubkeyLoad loads a public key from the opaque data structure
func pubkeyLoad(ge *GroupElementAffine, pubkey *PublicKey) bool {
	ge.fromBytes(pubkey.data[:])
	return !ge.x.isZero() // Basic validity check
}

// pubkeySave saves a group element to the public key data structure
func pubkeySave(pubkey *PublicKey, ge *GroupElementAffine) {
	ge.toBytes(pubkey.data[:])
}

// ecdsaSignatureLoad loads r and s scalars from signature
func ecdsaSignatureLoad(r, s *Scalar, sig *Signature) {
	r.setB32(sig.data[0:32])
	s.setB32(sig.data[32:64])
}

// ecdsaSignatureSave saves r and s scalars to signature
func ecdsaSignatureSave(sig *Signature, r, s *Scalar) {
	r.getB32(sig.data[0:32])
	s.getB32(sig.data[32:64])
}

// ecPubkeyCreateHelper creates a public key from a secret key
func ecPubkeyCreateHelper(ecmultGenCtx *EcmultGenContext, seckeyScalar *Scalar, point *GroupElementAffine, seckey []byte) bool {
	if !seckeyScalar.setB32Seckey(seckey) {
		return false
	}

	// Multiply generator by secret key: point = seckey * G
	var pointJ GroupElementJacobian
	ecmultGen(ecmultGenCtx, &pointJ, seckeyScalar)
	point.setGEJ(&pointJ)

	return true
}

// ecmultGen performs optimized scalar multiplication with the generator point
func ecmultGen(ctx *EcmultGenContext, r *GroupElementJacobian, a *Scalar) {
	if !ctx.built {
		panic("ecmult_gen context not built")
	}

	if a.isZero() {
		r.setInfinity()
		return
	}

	r.setInfinity()

	// Process scalar in 4-bit windows from least significant to most significant
	for i := 0; i < 64; i++ {
		bits := a.getBits(uint(i*4), 4)
		if bits != 0 {
			// Add precomputed point: bits * 2^(i*4) * G
			r.addGE(r, &ctx.prec[i][bits])
		}
	}

	// Apply blinding if enabled
	if !ctx.blindPoint.infinity {
		r.addGE(r, &ctx.blindPoint)
	}
}

// Placeholder implementations for complex functions

// ecKeyPubkeyParse parses a public key from various formats
func ecKeyPubkeyParse(ge *GroupElementAffine, input []byte) bool {
	if len(input) == 0 {
		return false
	}

	switch input[0] {
	case TagPubkeyUncompressed:
		if len(input) != 65 {
			return false
		}
		var x, y FieldElement
		x.setB32(input[1:33])
		y.setB32(input[33:65])
		ge.setXY(&x, &y)
		return ge.isValid()

	case TagPubkeyEven, TagPubkeyOdd:
		if len(input) != 33 {
			return false
		}
		var x FieldElement
		x.setB32(input[1:33])
		return ge.setXOVar(&x, input[0] == TagPubkeyOdd)

	default:
		return false
	}
}

// ecKeyPubkeySerialize serializes a public key
func ecKeyPubkeySerialize(ge *GroupElementAffine, output []byte, compressed bool) int {
	if compressed {
		if len(output) < 33 {
			return 0
		}

		var x FieldElement
		x = ge.x
		x.normalize()

		if ge.y.isOdd() {
			output[0] = TagPubkeyOdd
		} else {
			output[0] = TagPubkeyEven
		}

		x.getB32(output[1:33])
		return 33
	} else {
		if len(output) < 65 {
			return 0
		}

		var x, y FieldElement
		x = ge.x
		y = ge.y
		x.normalize()
		y.normalize()

		output[0] = TagPubkeyUncompressed
		x.getB32(output[1:33])
		y.getB32(output[33:65])
		return 65
	}
}

// Placeholder ECDSA functions (simplified implementations)

func ecdsaSigParse(r, s *Scalar, input []byte) bool {
	// Simplified DER parsing - real implementation needs proper ASN.1 parsing
	if len(input) < 6 {
		return false
	}

	// For now, assume it's already in the right format
	if len(input) >= 64 {
		r.setB32(input[0:32])
		s.setB32(input[32:64])
		return true
	}

	return false
}

func ecdsaSigSerialize(output []byte, outputlen *int, r, s *Scalar) bool {
	// Simplified DER serialization
	if len(output) < 64 {
		return false
	}

	r.getB32(output[0:32])
	s.getB32(output[32:64])
	*outputlen = 64

	return true
}

func ecdsaSigVerify(r, s *Scalar, pubkey *GroupElementAffine, message *Scalar) bool {
	// Simplified ECDSA verification
	// Real implementation needs proper elliptic curve operations

	if r.isZero() || s.isZero() {
		return false
	}

	// This is a placeholder - real verification is much more complex
	return true
}

func ecdsaSignInner(ctx *Context, r, s *Scalar, recid *int, msghash32 []byte, seckey []byte, noncefp NonceFunction, ndata interface{}) bool {
	var sec, nonce, msg Scalar

	if !sec.setB32Seckey(seckey) {
		return false
	}

	msg.setB32(msghash32)

	if noncefp == nil {
		noncefp = NonceFunctionDefault
	}

	// Generate nonce
	var nonce32 [32]byte
	attempt := uint(0)

	for {
		if !noncefp(nonce32[:], msghash32, seckey, nil, ndata, attempt) {
			return false
		}

		if !nonce.setB32Seckey(nonce32[:]) {
			attempt++
			continue
		}

		// Compute signature
		if ecdsaSigSign(&ctx.ecmultGenCtx, r, s, &sec, &msg, &nonce, recid) {
			break
		}

		attempt++
		if attempt > 1000 { // Prevent infinite loop
			return false
		}
	}

	return true
}

func ecdsaSigSign(ecmultGenCtx *EcmultGenContext, r, s *Scalar, seckey, message, nonce *Scalar, recid *int) bool {
	// Simplified ECDSA signing
	// Real implementation needs proper elliptic curve operations

	// This is a placeholder implementation
	*r = *nonce
	*s = *seckey
	s.mul(s, message)

	return true
}

// RFC 6979 nonce generation
func rfc6979NonceFunction(nonce32 []byte, msg32 []byte, key32 []byte, algo16 []byte, data interface{}, attempt uint) bool {
	if len(nonce32) != 32 || len(msg32) != 32 || len(key32) != 32 {
		return false
	}

	// Build input data for HMAC: key || msg || [extra_data] || [algo]
	var keyData []byte
	keyData = append(keyData, key32...)
	keyData = append(keyData, msg32...)

	// Add extra entropy if provided
	if data != nil {
		if extraBytes, ok := data.([]byte); ok && len(extraBytes) == 32 {
			keyData = append(keyData, extraBytes...)
		}
	}

	// Add algorithm identifier if provided
	if algo16 != nil && len(algo16) == 16 {
		keyData = append(keyData, algo16...)
	}

	// Initialize RFC 6979 HMAC
	rng := NewRFC6979HMACSHA256()
	rng.Initialize(keyData)

	// Generate nonces until we get the right attempt
	var tempNonce [32]byte
	for i := uint(0); i <= attempt; i++ {
		rng.Generate(tempNonce[:])
	}

	copy(nonce32, tempNonce[:])
	rng.Clear()

	return true
}
