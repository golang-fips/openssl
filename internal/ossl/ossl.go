// Package ossl provides a Go interface to OpenSSL.
package ossl

//go:generate go run ../../cmd/mkcgo -out zossl.go -package ossl shims.h

/*
#include "zossl.h"
*/
import "C"
import "unsafe"

func HashSum(ctx1, ctx2 EVP_MD_CTX_PTR, out []byte) error {
	var errst C.mkcgo_err_state
	if C._mkcgo_EVP_MD_CTX_copy(ctx2, ctx1, mkcgoNoEscape(&errst)) != 1 {
		return newMkcgoErr("EVP_MD_CTX_copy", errst)
	}
	if C._mkcgo_EVP_DigestFinal_ex(ctx2, (*C.uchar)(unsafe.SliceData(out)), nil, mkcgoNoEscape(&errst)) <= 0 {
		return newMkcgoErr("EVP_DigestFinal_ex", errst)
	}

	return nil
}
