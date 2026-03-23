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
import btcecc "github.com/guibressan/btcecc.git"

ctx := btcecc.ContextCreate(btcecc.ContextNone)
defer ctx.Destroy()

pub, ok := btcecc.ECPubKeyParse(ctx, pubkeyBytes)
sig, ok := btcecc.ECDSASignatureParseCompact(ctx, sigBytes)
btcecc.ECDSASignatureNormalize(ctx, sig)
valid := btcecc.ECDSAVerify(ctx, sig, msgHashBytes, pub)
```
