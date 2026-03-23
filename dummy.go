// This file is a workaround: go mod vendor ignores directories that contain
// no Go files, which would cause the vendored C source directories under
// secp256k1/ to be omitted. By declaring them as packages (guarded by the
// never-satisfied "dummy" build tag so they are never compiled), the vendor
// command includes them.
//go:build dummy
package btcecc

import (
	_ "github.com/guibressan/secp256k1/secp256k1/src"
	_ "github.com/guibressan/secp256k1/secp256k1/include"
)
