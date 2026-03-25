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

// ECPubKeySerializeUncompressed writes the 65-byte uncompressed 0x04||x||y
// form of pub into uncompressedOut for contexts that require the full
// coordinates, such as legacy Bitcoin address generation.
// pub is expected to be non-nil.
// uncompressedOut is expected to be at least 65 bytes.
func ECPubKeySerializeUncompressed(pub *PubKey, uncompressedOut []byte) {
	outputlen := C.size_t(len(uncompressedOut))
	C.secp256k1_ec_pubkey_serialize(
		ctx,
		(*C.uchar)(unsafe.Pointer(&uncompressedOut[0])),
		&outputlen,
		&pub.inner,
		C.SECP256K1_EC_UNCOMPRESSED,
	)
}

// ECPubKeySerializeCompressed writes the 33-byte compressed 0x02/0x03||x form
// of pub into compressedOut for use in modern Bitcoin transactions and
// addresses where minimizing script size matters.
// pub is expected to be non-nil.
// compressedOut is expected to be at least 33 bytes.
func ECPubKeySerializeCompressed(pub *PubKey, compressedOut []byte) {
	outputlen := C.size_t(len(compressedOut))
	C.secp256k1_ec_pubkey_serialize(
		ctx,
		(*C.uchar)(unsafe.Pointer(&compressedOut[0])),
		&outputlen,
		&pub.inner,
		C.SECP256K1_EC_COMPRESSED,
	)
}

// ECSecKeyVerify checks that seckey is a valid secp256k1 secret key —
// non-zero and less than the curve order — to guard against using a
// broken randomness source before performing any signing operations.
// seckey is expected to be exactly 32 bytes.
func ECSecKeyVerify(seckey []byte) bool {
	ret := C.secp256k1_ec_seckey_verify(
		ctx,
		(*C.uchar)(unsafe.Pointer(&seckey[0])),
	)
	return ret == 1
}

// ECPubKeyCreate derives the public key from seckey so callers can
// obtain a verifiable identity without performing manual elliptic-curve
// point multiplication.
// seckey is expected to be exactly 32 bytes and valid per ECSecKeyVerify.
func ECPubKeyCreate(seckey []byte) (*PubKey, bool) {
	pub := &PubKey{}
	ret := C.secp256k1_ec_pubkey_create(
		ctx, &pub.inner,
		(*C.uchar)(unsafe.Pointer(&seckey[0])),
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

// ECDSASignatureParseDER parses a DER-encoded ECDSA signature to allow
// verification of Bitcoin transactions that encode signatures in DER
// format, as required by BIP66.
// derSig is expected to be non-empty.
func ECDSASignatureParseDER(derSig []byte) (*Signature, bool) {
	sig := &Signature{}
	ret := C.secp256k1_ecdsa_signature_parse_der(
		ctx, &sig.inner,
		(*C.uchar)(unsafe.Pointer(&derSig[0])),
		C.size_t(len(derSig)),
	)
	return sig, ret == 1
}

// ECDSASignatureSerializeDER writes the DER encoding of sig into derOut and
// returns the number of bytes written, enabling embedding in Bitcoin
// transaction inputs which mandate DER format per BIP66.
// sig is expected to be non-nil. derOut is expected to be at least 72 bytes.
func ECDSASignatureSerializeDER(sig *Signature, derOut []byte) int {
	derlen := C.size_t(len(derOut))
	C.secp256k1_ecdsa_signature_serialize_der(
		ctx,
		(*C.uchar)(unsafe.Pointer(&derOut[0])),
		&derlen,
		&sig.inner,
	)
	return int(derlen)
}

// ECDSASignatureSerializeCompact writes the 64-byte compact R||S encoding of
// sig into compactOut for use in off-chain protocols and storage formats where
// space efficiency is required.
// sig is expected to be non-nil.
// compactOut is expected to be at least 64 bytes.
func ECDSASignatureSerializeCompact(sig *Signature, compactOut []byte) {
	C.secp256k1_ecdsa_signature_serialize_compact(
		ctx,
		(*C.uchar)(unsafe.Pointer(&compactOut[0])),
		&sig.inner,
	)
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

// ECDSASign creates a lower-S normalized ECDSA signature for msgHash using
// seckey, enabling Bitcoin transaction signing without relying on external
// elliptic-curve implementations.
// msgHash is expected to be exactly 32 bytes.
// seckey is expected to be exactly 32 bytes and valid per ECSecKeyVerify.
func ECDSASign(msgHash, seckey []byte) (*Signature, bool) {
	sig := &Signature{}
	ret := C.secp256k1_ecdsa_sign(
		ctx, &sig.inner,
		(*C.uchar)(unsafe.Pointer(&msgHash[0])),
		(*C.uchar)(unsafe.Pointer(&seckey[0])),
		nil,
		nil,
	)
	return sig, ret == 1
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
