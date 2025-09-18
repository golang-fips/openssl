//go:build !cgo

package ossl

import (
	"unsafe"
)

func dlsym(handle unsafe.Pointer, symbol string, optional bool) unsafe.Pointer {
	r0, _, err := Dlsym(uintptr(handle), unsafe.StringData(symbol))
	if err != 0 {
		if !optional {
			panic("cannot get required symbol " + symbol + ": " + err.Error())
		}
		return nil
	}
	return unsafe.Pointer(r0), nil
}

// HashSum copies ctx1 into ctx2 and calls EVP_DigestFinal_ex using ctx2.
// This is necessary because Go hash.Hash mandates that Sum has no effect
// on the underlying stream. In particular it is OK to Sum, then Write more,
// then Sum again, and the second Sum acts as if the first didn't happen.
func HashSum(ctx1, ctx2 EVP_MD_CTX_PTR, out []byte) error {
	// Clear any existing errors
	ERR_clear_error()

	// Copy ctx1 to ctx2 using EVP_MD_CTX_copy_ex
	code, err := EVP_MD_CTX_copy_ex(ctx2, ctx1)
	if err != nil {
		return err
	}
	if code != 1 {
		return newMkcgoErr("EVP_MD_CTX_copy_ex", nil)
	}

	// Finalize the hash using ctx2
	code, err = EVP_DigestFinal_ex(ctx2, (*byte)(unsafe.SliceData(out)), nil)
	if err != nil {
		return err
	}
	if code <= 0 {
		return newMkcgoErr("EVP_DigestFinal_ex", nil)
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

// goString converts a C string (byte pointer) to a Go string
func goString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var result []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + i))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}
