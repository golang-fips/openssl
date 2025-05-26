// Package ossl provides a Go interface to OpenSSL.
package ossl

//go:generate go run ../../cmd/mkcgo -out zossl.go -package ossl shims.h

/*
#include "zossl.h"
// go_hash_sum copies ctx into ctx2 and calls EVP_DigestFinal_ex using ctx2.
// This is necessary because Go hash.Hash mandates that Sum has no effect
// on the underlying stream. In particular it is OK to Sum, then Write more,
// then Sum again, and the second Sum acts as if the first didn't happen.
// It is written in C because Sum() tend to be in the hot path,
// and doing one cgo call instead of two is a significant performance win.
static inline int
go_hash_sum(const _EVP_MD_CTX_PTR ctx, _EVP_MD_CTX_PTR ctx2, unsigned char *out, mkcgo_err_state *_err_state)
{
	if (_mkcgo_EVP_MD_CTX_copy(ctx2, ctx, _err_state) != 1)
		return -1;
	if (_mkcgo_EVP_DigestFinal_ex(ctx2, out, NULL, _err_state) <= 0)
		return -2;
	return 1;
}
*/
import "C"
import (
	"unsafe"
)

func HashSum(ctx1, ctx2 EVP_MD_CTX_PTR, out []byte) error {
	var errst C.mkcgo_err_state
	if code := C.go_hash_sum(ctx1, ctx2, (*C.uchar)(unsafe.SliceData(out)), mkcgoNoEscape(&errst)); code != 1 {
		msg := "go_hash_sum"
		switch code {
		case -1:
			msg = "EVP_MD_CTX_copy"
		case -2:
			msg = "EVP_DigestFinal_ex"
		}
		return newMkcgoErr(msg, errst)
	}
	return nil
}

const _OSSL_PARAM_UNMODIFIED uint = uint(^uintptr(0))

// OSSL_PARAM is a structure to pass or request object parameters.
// https://docs.openssl.org/3.0/man3/OSSL_PARAM/.
type OSSL_PARAM struct {
	Key        *byte
	DataType   uint32
	Data       unsafe.Pointer
	DataSize   uint
	ReturnSize uint
}

func ossl_param_construct(key *byte, dataType uint32, data unsafe.Pointer, dataSize int) OSSL_PARAM {
	return OSSL_PARAM{
		Key:        key,
		DataType:   dataType,
		Data:       data,
		DataSize:   uint(dataSize),
		ReturnSize: _OSSL_PARAM_UNMODIFIED,
	}
}

func OSSL_PARAM_construct_octet_string(key *byte, data unsafe.Pointer, dataSize int) OSSL_PARAM {
	return ossl_param_construct(key, OSSL_PARAM_OCTET_STRING, data, dataSize)
}

func OSSL_PARAM_construct_int32(key *byte, data *int32) OSSL_PARAM {
	return ossl_param_construct(key, OSSL_PARAM_INTEGER, unsafe.Pointer(data), 4)
}

func OSSL_PARAM_construct_end() OSSL_PARAM {
	return OSSL_PARAM{}
}

func OSSL_PARAM_modified(param *OSSL_PARAM) bool {
	// If ReturnSize is not set, the parameter has not been modified.
	return param != nil && param.ReturnSize != _OSSL_PARAM_UNMODIFIED
}
