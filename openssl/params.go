//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

// #include "goopenssl.h"
import "C"
import (
	"encoding/binary"
	"unsafe"
)

var paramEnd = C.GO_OSSL_PARAM{
	key:         nil,
	data_type:   0,
	data:        nil,
	data_size:   0,
	return_size: 0,
}

// paramsBuilder is a container for OSSL_PARAMs.
// It must be freed using paramsBuilder.free().
type paramsBuilder struct {
	params []C.GO_OSSL_PARAM
}

func newParamsBuilder() paramsBuilder {
	var pb paramsBuilder
	pb.params = make([]C.GO_OSSL_PARAM, 1, 5)
	pb.params[0] = paramEnd
	return pb
}

func (pb *paramsBuilder) free() {
	C._goboringcrypto_params_free(&pb.params[0])
	pb.params = pb.params[:1]
	pb.params[0] = paramEnd
}

// addUTF8 adds a parameter of type data_type.
// data is stored in the new parameter without copying,
// so any change to its content after this call will also
// affect the created parameter.
func (pb *paramsBuilder) add(key *C.char, data_type C.uint, data unsafe.Pointer, data_size C.size_t) {
	if key == nil {
		panic("key shouldn't be nil")
	}
	var return_size = C.GO_OSSL_PARAM_UNMODIFIED
	pb.params[len(pb.params)-1] = C.GO_OSSL_PARAM{
		key:         key,
		data_type:   data_type,
		data:        data,
		data_size:   data_size,
		return_size: C.size_t(return_size),
	}
	pb.params = append(pb.params, paramEnd)
}

// addUTF8 adds a parameter of type OSSL_PARAM_UTF8_STRING.
func (pb *paramsBuilder) addUTF8(key *C.char, v string) {
	pb.add(key, C.GO_OSSL_PARAM_UTF8_STRING, unsafe.Pointer(C.CString(v)), C.size_t(len(v)))
}

// addOctetString adds a parameter of type OSSL_PARAM_OCTET_STRING.
// The content of v is copied into the new param,
// it's safe to change it after this call.
func (pb *paramsBuilder) addOctetString(key *C.char, v []byte) {
	pb.add(key, C.GO_OSSL_PARAM_OCTET_STRING, C.CBytes(v), C.size_t(len(v)))
}

// addBigNumber adds a parameter of type OSSL_PARAM_UNSIGNED_INTEGER.
// The content of v is copied into the new param,
// it's safe to change it after this call.
func (pb *paramsBuilder) addBigNumber(key *C.char, v []byte) error {
	cbytes := (*C.uchar)(C.CBytes(v))
	if nativeEndian != binary.BigEndian {
		// The original bytes represent a big number using big-endian.
		// Unfortunately, OpenSSL expects that big numbers are passed using native-endian.
		// The following call re-encodes cbytes as little-endian.
		// We would have to to this even if we called OSSL_PARAM_construct_BN,
		// as it also expect a native-endian number.
		priv := C._goboringcrypto_BN_bin2bn(cbytes, C.size_t(len(v)), nil)
		if priv == nil {
			return NewOpenSSLError("BN_bin2bn")
		}
		defer C._goboringcrypto_BN_free(priv)
		if C._goboringcrypto_BN_bn2lebinpad(priv, cbytes, C.size_t(len(v))) == -1 {
			return NewOpenSSLError("BN_bn2lebinpad")
		}
	}
	pb.add(key, C.GO_OSSL_PARAM_UNSIGNED_INTEGER, unsafe.Pointer(cbytes), C.size_t(len(v)))
	return nil
}
