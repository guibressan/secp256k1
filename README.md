# secp256k1

Go CGO bindings for [libsecp256k1](https://github.com/bitcoin-core/secp256k1),
the elliptic curve library used by Bitcoin.

The library is compiled from source at build time — no pre-built binaries
required. A plain `go build` or `go test` is sufficient.

## Requirements

- Go 1.26+
- A C compiler

## Contributing

See [contribution guide](docs/contribution_guide.md).

## Usage

```go
import "github.com/guibressan/secp256k1"

pub, ok := secp256k1.ECPubKeyParse(pubkeyBytes)
sig, ok := secp256k1.ECDSASignatureParseCompact(sigBytes)
secp256k1.ECDSASignatureNormalize(sig)
valid := secp256k1.ECDSAVerify(sig, msgHashBytes, pub)
```
