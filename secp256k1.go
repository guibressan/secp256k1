package btcecc

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

type PubKey struct {
	inner C.secp256k1_pubkey
}

func ECPubKeyParse(input []byte) (*PubKey, bool) {
	pub := &PubKey{}
	ret := C.secp256k1_ec_pubkey_parse(
		ctx, &pub.inner,
		(*C.uchar)(unsafe.Pointer(&input[0])),
		C.size_t(len(input)),
	)
	return pub, ret == 1
}

type Signature struct {
	inner C.secp256k1_ecdsa_signature
}

func ECDSASignatureParseCompact(input []byte) (*Signature, bool) {
	sig := &Signature{}
	ret := C.secp256k1_ecdsa_signature_parse_compact(
		ctx, &sig.inner,
		(*C.uchar)(unsafe.Pointer(&input[0])),
	)
	return sig, ret == 1
}

func ECDSASignatureNormalize(sig *Signature) bool {
	ret := C.secp256k1_ecdsa_signature_normalize(
		ctx, &sig.inner, &sig.inner,
	)
	return ret == 1
}

func ECDSAVerify(sig *Signature, msgHash []byte,
	pub *PubKey) bool {

	ret := C.secp256k1_ecdsa_verify(
		ctx, &sig.inner,
		(*C.uchar)(unsafe.Pointer(&msgHash[0])),
		&pub.inner,
	)
	return ret == 1
}
