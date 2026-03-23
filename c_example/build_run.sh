#!/usr/bin/env bash

readonly RELDIR="$(dirname ${0})"
readonly SECP="${RELDIR}/../secp256k1"

set -e

mkdir -p ${RELDIR}/build

CFLAGS="-I${SECP}/include -I${SECP}/src -O2"

zig cc -o ${RELDIR}/build/test \
	${CFLAGS} \
	${RELDIR}/test.c \
	${SECP}/src/secp256k1.c \
	${SECP}/src/precomputed_ecmult_gen.c \
	${SECP}/src/precomputed_ecmult.c

./${RELDIR}/build/test
