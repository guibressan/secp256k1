# secp256k1

Go CGO bindings for [libsecp256k1](https://github.com/bitcoin-core/secp256k1),
the elliptic curve library used by Bitcoin. Created to improve the speed of
block validation in the [btcd](https://github.com/btcsuite/btcd) project.

The library is compiled from source at build time — no pre-built binaries
required. A plain `go build` or `go test` is sufficient.

## Benchmark results

```
goos: darwin
goarch: arm64
pkg: github.com/guibressan/secp256k1/benchmarks
cpu: Apple M1
BenchmarkLibsecp256k1ECDSAVerifyParallel-8   	   50000	      5090 ns/op	       0 B/op	       0 allocs/op
BenchmarkLibsecp256k1ECDSAVerify-8           	   50000	     23435 ns/op	       0 B/op	       0 allocs/op
BenchmarkDecredECDSAVerifyParallel-8         	   50000	     24798 ns/op	     568 B/op	      12 allocs/op
BenchmarkDecredECDSAVerify-8                 	   50000	    132083 ns/op	     568 B/op	      12 allocs/op
BenchmarkGocoinECDSAVerifyParallel-8         	   50000	     12131 ns/op	    9109 B/op	     213 allocs/op
BenchmarkGocoinECDSAVerify-8                 	   50000	     51075 ns/op	    9108 B/op	     213 allocs/op

```

## Requirements

- Go 1.26+
- A C compiler

## Testing

```
go test ./...
```

## Benchmarking

```
cd benchmarks

go test -bench=. -benchtime=10s
```

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
