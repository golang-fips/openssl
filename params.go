//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"math"
	"unsafe"
)

// _OSSL_PARAM is a structure to pass or request object parameters.
// https://docs.openssl.org/3.0/man3/OSSL_PARAM/.
type _OSSL_PARAM struct {
	Key        *C.char
	DataType   uint32
	Data       unsafe.Pointer
	DataSize   int
	ReturnSize int
}

func ossl_param_construct(key *C.char, dataType uint32, data unsafe.Pointer, dataSize int) _OSSL_PARAM {
	return _OSSL_PARAM{
		Key:        key,
		DataType:   dataType,
		Data:       data,
		DataSize:   dataSize,
		ReturnSize: math.MaxInt - 1,
	}
}

func _OSSL_PARAM_construct_octet_string(key *C.char, data unsafe.Pointer, dataSize int) _OSSL_PARAM {
	return ossl_param_construct(key, C.GO_OSSL_PARAM_OCTET_STRING, data, dataSize)
}

func _OSSL_PARAM_construct_end() _OSSL_PARAM {
	return _OSSL_PARAM{}
}
