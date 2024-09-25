//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"runtime"
	"unsafe"
)

var (
	// KDF parameters
	_OSSL_KDF_PARAM_DIGEST = C.CString("digest")
	_OSSL_KDF_PARAM_SECRET = C.CString("secret")
	_OSSL_KDF_PARAM_SEED   = C.CString("seed")
	_OSSL_KDF_PARAM_KEY    = C.CString("key")
	_OSSL_KDF_PARAM_INFO   = C.CString("info")
	_OSSL_KDF_PARAM_SALT   = C.CString("salt")
	_OSSL_KDF_PARAM_MODE   = C.CString("mode")
)

// paramBuilder is a helper for building OSSL_PARAMs.
// If an error occurs when adding a new parameter,
// subsequent calls to add parameters are ignored
// and build() will return the error.
type paramBuilder struct {
	bld    C.GO_OSSL_PARAM_BLD_PTR
	pinner runtime.Pinner

	err error
}

// newParamBuilder creates a new paramBuilder.
func newParamBuilder() (*paramBuilder, error) {
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	pb := &paramBuilder{bld: bld}
	runtime.SetFinalizer(pb, (*paramBuilder).finalize)
	return pb, nil
}

// finalize frees the builder.
func (b *paramBuilder) finalize() {
	if b.bld != nil {
		b.pinner.Unpin()
		C.go_openssl_OSSL_PARAM_BLD_free(b.bld)
		b.bld = nil
	}
}

// check is used internally to enforce invariants and should not be called by users of paramBuilder.
// Returns true if it's ok to add parameters to the builder or build it.
// Returns false if there has been an error while adding a parameter.
// Panics if the paramBuilder has been freed, e.g. if it has already been built.
func (b *paramBuilder) check() bool {
	if b.err != nil {
		return false
	}
	if b.bld == nil {
		panic("openssl: paramBuilder has been freed")
	}
	return true
}

// build creates an OSSL_PARAM from the builder.
// The returned OSSL_PARAM must be freed with OSSL_PARAM_free.
// If an error occurred while adding parameters, the error is returned
// and the OSSL_PARAM is nil. Once build() is called, the builder is finalized
// and cannot be reused.
func (b *paramBuilder) build() (C.GO_OSSL_PARAM_PTR, error) {
	defer b.finalize()
	if !b.check() {
		return nil, b.err
	}
	param := C.go_openssl_OSSL_PARAM_BLD_to_param(b.bld)
	if param == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_build")
	}
	return param, nil
}

// addUTF8String adds a NUL-terminated UTF-8 string to the builder.
// size should not include the terminating NUL byte. If size is zero, then it will be calculated.
func (b *paramBuilder) addUTF8String(name *C.char, value *C.char, size C.size_t) {
	if !b.check() {
		return
	}
	// OSSL_PARAM_BLD_push_utf8_string calculates the size if it is zero.
	if C.go_openssl_OSSL_PARAM_BLD_push_utf8_string(b.bld, name, value, size) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_utf8_string(" + C.GoString(name) + ")")
	}
}

// addOctetString adds an octet string to the builder.
// The value is pinned and will be unpinned when the builder is freed.
func (b *paramBuilder) addOctetString(name *C.char, value []byte) {
	if !b.check() {
		return
	}
	if len(value) != 0 {
		b.pinner.Pin(&value[0])
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_octet_string(b.bld, name, unsafe.Pointer(sbase(value)), C.size_t(len(value))) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_octet_string(" + C.GoString(name) + ")")
	}
}

// addIn32 adds a int32 to the builder.
func (b *paramBuilder) addInt32(name *C.char, value int32) {
	if !b.check() {
		return
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_int32(b.bld, name, C.int32_t(value)) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_int32(" + C.GoString(name) + ")")
	}
}
