.PHONY: fmt

fmt:
	find . -type f -not -path './secp256k1/*' -name '*.go' | xargs gofmt -w
