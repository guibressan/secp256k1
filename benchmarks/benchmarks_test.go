package benchmarks_test

import (
	"testing"

	secp "github.com/guibressan/secp256k1"
	gocoin "github.com/piotrnar/gocoin/lib/secp256k1"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	dcr "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var ecdsaVerifyCommon = struct {
	pubkey  []byte
	sighash []byte
	sig     []byte
}{
	pubkey: []byte{
		0x04, 0xb0, 0xe2, 0xc8, 0x79, 0xe4, 0xda, 0xf7, 0xb9, 0xab,
		0x68, 0x35, 0x02, 0x28, 0xc1, 0x59, 0x76, 0x66, 0x76, 0xa1,
		0x4f, 0x58, 0x15, 0x08, 0x4b, 0xa1, 0x66, 0x43, 0x2a, 0xab,
		0x46, 0x19, 0x8d, 0x4c, 0xca, 0x98, 0xfa, 0x3e, 0x99, 0x81,
		0xd0, 0xa9, 0x0b, 0x2e, 0xff, 0xc5, 0x14, 0xb7, 0x62, 0x79,
		0x47, 0x65, 0x50, 0xba, 0x36, 0x63, 0xfd, 0xca, 0xff, 0x94,
		0xc3, 0x84, 0x20, 0xe9, 0xd5,
	},
	sighash: []byte{
		0x11, 0x74, 0x3b, 0x22, 0x0e, 0x9e, 0x24, 0xe8, 0x9a, 0xbd,
		0x4f, 0xf1, 0x24, 0xa2, 0x74, 0x05, 0x31, 0xfe, 0x7d, 0x7f,
		0x9b, 0x4e, 0x26, 0xde, 0x14, 0x71, 0x0a, 0x53, 0x2f, 0xd5,
		0x43, 0xe2,
	},
	sig: []byte{
		0xd2, 0x34, 0x59, 0xd0, 0x3e, 0xd7, 0xe9, 0x51, 0x1a, 0x47,
		0xd1, 0x32, 0x92, 0xd3, 0x43, 0x0a, 0x04, 0x62, 0x7d, 0xe6,
		0x23, 0x5b, 0x6e, 0x51, 0xa4, 0x0f, 0x9c, 0xd3, 0x86, 0xf2,
		0xab, 0xe3, 0xe7, 0xd2, 0x5b, 0x08, 0x0f, 0x0b, 0xb8, 0xd8,
		0xd5, 0xf8, 0x78, 0xbb, 0xa7, 0xd5, 0x4a, 0xd2, 0xfd, 0xa6,
		0x50, 0xea, 0x8d, 0x15, 0x8a, 0x33, 0xee, 0x3c, 0xbd, 0x11,
		0x76, 0x81, 0x91, 0xfd,
	},
}

func BenchmarkLibsecp256k1ECDSAVerifyParallel(b *testing.B) {
	pub, ok := secp.ECPubKeyParse(ecdsaVerifyCommon.pubkey)
	if !ok {
		b.Fatal("failed to parse pubkey")
	}

	sig, ok := secp.ECDSASignatureParseCompact(ecdsaVerifyCommon.sig)
	if !ok {
		b.Fatal("failed to parse compact signature")
	}

	secp.ECDSASignatureNormalize(sig)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !secp.ECDSAVerify(sig, ecdsaVerifyCommon.sighash, pub) {
				b.Fatal("signature verification failed")
			}
		}
	})
}

func BenchmarkLibsecp256k1ECDSAVerify(b *testing.B) {
	pub, ok := secp.ECPubKeyParse(ecdsaVerifyCommon.pubkey)
	if !ok {
		b.Fatal("failed to parse pubkey")
	}

	sig, ok := secp.ECDSASignatureParseCompact(ecdsaVerifyCommon.sig)
	if !ok {
		b.Fatal("failed to parse compact signature")
	}

	secp.ECDSASignatureNormalize(sig)

	for range b.N {
		if !secp.ECDSAVerify(sig, ecdsaVerifyCommon.sighash, pub) {
			b.Fatal("signature verification failed")
		}
	}
}


func BenchmarkDecredECDSAVerifyParallel(b *testing.B) {
	pub, err := dcr.ParsePubKey(ecdsaVerifyCommon.pubkey)
	if err != nil {
		b.Fatal("failed to parse pubkey:", err)
	}

	var r, s dcr.ModNScalar
	r.SetByteSlice(ecdsaVerifyCommon.sig[:32])
	s.SetByteSlice(ecdsaVerifyCommon.sig[32:])
	sig := dcrecdsa.NewSignature(&r, &s)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !sig.Verify(ecdsaVerifyCommon.sighash, pub) {
				b.Fatal("signature verification failed")
			}
		}
	})
}

func BenchmarkDecredECDSAVerify(b *testing.B) {
	pub, err := dcr.ParsePubKey(ecdsaVerifyCommon.pubkey)
	if err != nil {
		b.Fatal("failed to parse pubkey:", err)
	}

	var r, s dcr.ModNScalar
	r.SetByteSlice(ecdsaVerifyCommon.sig[:32])
	s.SetByteSlice(ecdsaVerifyCommon.sig[32:])
	sig := dcrecdsa.NewSignature(&r, &s)

	for range b.N {
		if !sig.Verify(ecdsaVerifyCommon.sighash, pub) {
			b.Fatal("signature verification failed")
		}
	}
}

func BenchmarkGocoinECDSAVerifyParallel(b *testing.B) {
	var pub gocoin.XY
	if !pub.ParsePubkey(ecdsaVerifyCommon.pubkey) {
		b.Fatal("failed to parse pubkey")
	}

	var sig gocoin.Signature
	sig.R.SetBytes(ecdsaVerifyCommon.sig[:32])
	sig.S.SetBytes(ecdsaVerifyCommon.sig[32:])

	var msg gocoin.Number
	msg.SetBytes(ecdsaVerifyCommon.sighash)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !sig.Verify(&pub, &msg) {
				b.Fatal("signature verification failed")
			}
		}
	})
}

func BenchmarkGocoinECDSAVerify(b *testing.B) {
	var pub gocoin.XY
	if !pub.ParsePubkey(ecdsaVerifyCommon.pubkey) {
		b.Fatal("failed to parse pubkey")
	}

	var sig gocoin.Signature
	sig.R.SetBytes(ecdsaVerifyCommon.sig[:32])
	sig.S.SetBytes(ecdsaVerifyCommon.sig[32:])

	var msg gocoin.Number
	msg.SetBytes(ecdsaVerifyCommon.sighash)

	for range b.N {
		if !sig.Verify(&pub, &msg) {
			b.Fatal("signature verification failed")
		}
	}
}
