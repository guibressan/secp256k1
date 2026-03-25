// Package secp256k1 wraps libsecp256k1 to take advantage of its highly optimized
// ECDSA signature verification for Bitcoin transactions.
package secp256k1

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/secp256k1/include -I${SRCDIR}/secp256k1/src -I${SRCDIR}/secp256k1/contrib -O2

#include "secp256k1/src/secp256k1.c"
#include "secp256k1/src/precomputed_ecmult_gen.c"
#include "secp256k1/src/precomputed_ecmult.c"
#include "secp256k1/contrib/lax_der_parsing.c"
#include "secp256k1.h"
#include "secp256k1/contrib/lax_der_parsing.h"
*/
import "C"
import (
	"bytes"
	"unsafe"
)

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

// ECDSASignatureParseBER parses a lax DER-encoded ECDSA signature to
// enable validation of pre-BIP66 Bitcoin transactions that use BER
// encodings not accepted by the strict DER parser.
// berSig is expected to be non-empty.
func ECDSASignatureParseBER(berSig []byte) (*Signature, bool) {
	sig := &Signature{}
	ret := C.ecdsa_signature_parse_der_lax(
		ctx, &sig.inner,
		(*C.uchar)(unsafe.Pointer(&berSig[0])),
		C.size_t(len(berSig)),
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

// orderN is the secp256k1 group order n in big-endian form.
var orderN = [32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
	0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
}

// scalarInRange reports whether v (big-endian, leading zeros already stripped)
// is in [1, n-1] for the secp256k1 group order n.
func scalarInRange(v []byte) bool {
	if len(v) == 0 || len(v) > 32 {
		return false
	}
	if len(v) < 32 {
		return true
	}
	return bytes.Compare(v, orderN[:]) < 0
}

// ECDSASignatureDERFormatCheck reports whether sig is a valid strict
// DER-encoded ECDSA signature as required by BIP66. It checks both encoding
// rules and that R and S are in [1, n-1]; it does not verify the signature
// against a public key.
//
// The expected encoding format is:
//
//	0x30 <len> 0x02 <rlen> <R> 0x02 <slen> <S>
//
// where R and S are minimally encoded, unsigned, big-endian integers.
func ECDSASignatureDERFormatCheck(sig []byte) bool {
	// Valid DER signatures are between 8 and 72 bytes.
	n := len(sig)
	if n < 8 || n > 72 {
		return false
	}
	if sig[0] != 0x30 {
		return false
	}
	// Outer length: short form only, must equal len(sig)-2 exactly.
	if int(sig[1]) != n-2 {
		return false
	}
	pos := 2
	for i := 0; i < 2; i++ {
		if pos >= n || sig[pos] != 0x02 {
			return false
		}
		pos++
		if pos >= n {
			return false
		}
		ilen := int(sig[pos])
		// Long-form lengths are not allowed in strict DER.
		if ilen&0x80 != 0 || ilen == 0 || pos+1+ilen > n {
			return false
		}
		pos++
		v := sig[pos : pos+ilen]
		// Must not be negative.
		if v[0]&0x80 != 0 {
			return false
		}
		// Must not have an unnecessary leading zero.
		if len(v) > 1 && v[0] == 0x00 && v[1]&0x80 == 0 {
			return false
		}
		// Strip the allowed leading zero and verify value is in [1, n-1].
		stripped := v
		if len(stripped) > 0 && stripped[0] == 0x00 {
			stripped = stripped[1:]
		}
		if !scalarInRange(stripped) {
			return false
		}
		pos += ilen
	}
	// No trailing bytes allowed.
	return pos == n
}

// ECDSASignatureBERFormatCheck reports whether sig has the structural envelope
// of a BER-encoded ECDSA signature, as accepted by the lax DER parser used for
// pre-BIP66 Bitcoin transactions. Trailing bytes after S are permitted.
func ECDSASignatureBERFormatCheck(sig []byte) bool {
	n := len(sig)
	if n < 2 || sig[0] != 0x30 {
		return false
	}
	pos := 1
	// Read outer sequence length; skip extra bytes without validating value.
	lb := int(sig[pos])
	pos++
	if lb&0x80 != 0 {
		extra := lb & 0x7F
		if extra > n-pos {
			return false
		}
		pos += extra
	}
	// Read R and S integers.
	for i := 0; i < 2; i++ {
		if pos >= n || sig[pos] != 0x02 {
			return false
		}
		pos++
		if pos >= n {
			return false
		}
		lb = int(sig[pos])
		pos++
		var vlen int
		if lb&0x80 == 0 {
			vlen = lb
		} else {
			lbytes := lb & 0x7F
			if lbytes > n-pos {
				return false
			}
			// Strip leading zero bytes (lax parsing).
			for lbytes > 0 && sig[pos] == 0 {
				pos++
				lbytes--
			}
			if lbytes >= 8 {
				return false
			}
			for lbytes > 0 {
				vlen = (vlen << 8) | int(sig[pos])
				pos++
				lbytes--
			}
		}
		if vlen > n-pos {
			return false
		}
		pos += vlen
	}
	return true
}
