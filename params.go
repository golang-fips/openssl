//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"unsafe"
)

const _OSSL_PARAM_UNMODIFIED uint = uint(^uintptr(0))

// _OSSL_PARAM is a structure to pass or request object parameters.
// https://docs.openssl.org/3.0/man3/OSSL_PARAM/.
type _OSSL_PARAM struct {
	Key        *C.char
	DataType   uint32
	Data       unsafe.Pointer
	DataSize   uint
	ReturnSize uint
}

func ossl_param_construct(key *C.char, dataType uint32, data unsafe.Pointer, dataSize int) _OSSL_PARAM {
	return _OSSL_PARAM{
		Key:        key,
		DataType:   dataType,
		Data:       data,
		DataSize:   uint(dataSize),
		ReturnSize: _OSSL_PARAM_UNMODIFIED,
	}
}

func _OSSL_PARAM_construct_octet_string(key *C.char, data unsafe.Pointer, dataSize int) _OSSL_PARAM {
	return ossl_param_construct(key, C.GO_OSSL_PARAM_OCTET_STRING, data, dataSize)
}

func _OSSL_PARAM_construct_int32(key *C.char, data *int32) _OSSL_PARAM {
	return ossl_param_construct(key, C.GO_OSSL_PARAM_INTEGER, unsafe.Pointer(data), 4)
}

func _OSSL_PARAM_construct_end() _OSSL_PARAM {
	return _OSSL_PARAM{}
}

func _OSSL_PARAM_modified(param *_OSSL_PARAM) bool {
	// If ReturnSize is not set, the parameter has not been modified.
	return param != nil && param.ReturnSize != _OSSL_PARAM_UNMODIFIED
}
