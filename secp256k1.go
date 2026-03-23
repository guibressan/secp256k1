// Package secp256k1 wraps libsecp256k1 to take advantage of its highly optimized
// ECDSA signature verification for Bitcoin transactions.
package secp256k1

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/secp256k1/include -I${SRCDIR}/secp256k1/src -O2

#include "secp256k1/src/secp256k1.c"
#include "secp256k1/src/precomputed_ecmult_gen.c"
#include "secp256k1/src/precomputed_ecmult.c"
#include "secp256k1.h"
*/
import "C"
import "unsafe"

var ctx *C.secp256k1_context

func init() {
	ctx = C.secp256k1_context_create(C.SECP256K1_CONTEXT_NONE)
}

// PubKey holds a parsed secp256k1 public key in the library's internal
// representation, avoiding repeated parsing overhead across verifications.
type PubKey struct {
	inner C.secp256k1_pubkey
}

// ECPubKeyParse parses a compressed or uncompressed public key so it can be
// reused across multiple ECDSAVerify calls without re-parsing each time.
// pubkey is expected to be non-empty.
func ECPubKeyParse(pubkey []byte) (*PubKey, bool) {
	pub := &PubKey{}
	ret := C.secp256k1_ec_pubkey_parse(
		ctx, &pub.inner,
		(*C.uchar)(unsafe.Pointer(&pubkey[0])),
		C.size_t(len(pubkey)),
	)
	return pub, ret == 1
}

// Signature holds a parsed ECDSA signature in the library's internal
// representation, decoupling parsing from verification.
type Signature struct {
	inner C.secp256k1_ecdsa_signature
}

// ECDSASignatureParseCompact parses a 64-byte compact-encoded ECDSA signature
// so it can be normalized and verified independently of parsing.
// compactSig is expected to be exactly 64 bytes.
func ECDSASignatureParseCompact(compactSig []byte) (*Signature, bool) {
	sig := &Signature{}
	ret := C.secp256k1_ecdsa_signature_parse_compact(
		ctx, &sig.inner,
		(*C.uchar)(unsafe.Pointer(&compactSig[0])),
	)
	return sig, ret == 1
}

// ECDSASignatureNormalize converts a signature to lower-S form to ensure
// a canonical representation, preventing signature malleability issues.
// sig is expected to be non-nil.
func ECDSASignatureNormalize(sig *Signature) bool {
	ret := C.secp256k1_ecdsa_signature_normalize(
		ctx, &sig.inner, &sig.inner,
	)
	return ret == 1
}

// ECDSAVerify checks that sig is a valid ECDSA signature of msgHash under pub,
// enabling Bitcoin transaction input validation against a known public key.
// sig and pub are expected to be non-nil. msgHash is expected to be 32 bytes.
func ECDSAVerify(sig *Signature, msgHash []byte,
	pub *PubKey) bool {

	ret := C.secp256k1_ecdsa_verify(
		ctx, &sig.inner,
		(*C.uchar)(unsafe.Pointer(&msgHash[0])),
		&pub.inner,
	)
	return ret == 1
}
