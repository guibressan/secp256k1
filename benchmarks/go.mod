module github.com/guibressan/secp256k1/benchmarks

go 1.23.2

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/guibressan/secp256k1 v0.0.0
	github.com/piotrnar/gocoin v0.0.0-20260325071953-f52caccca472
)

replace github.com/guibressan/secp256k1 => ../
