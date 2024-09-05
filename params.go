//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"runtime"
	"unsafe"
)

// paramBuilder is a helper for building OSSL_PARAMs.
// Any error that occurs when adding parameters is stored
// and returned when build() is called.
type paramBuilder struct {
	bld    C.GO_OSSL_PARAM_BLD_PTR
	pinner runtime.Pinner

	err error
}

// newParamBuilder creates a new paramBuilder.
// It must be freed with free() when done.
func newParamBuilder() (*paramBuilder, error) {
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	return &paramBuilder{bld: bld}, nil
}

func (b *paramBuilder) free() {
	if b.bld != nil {
		b.pinner.Unpin()
		C.go_openssl_OSSL_PARAM_BLD_free(b.bld)
		b.bld = nil
	}
}

func (b *paramBuilder) check() error {
	if b.err != nil {
		return b.err
	}
	if b.bld == nil {
		panic("openssl: paramBuilder is nil")
	}
	return nil
}

// build creates an OSSL_PARAM from the builder.
// The returned OSSL_PARAM must be freed with OSSL_PARAM_free.
// If an error occurred during building, it is returned.
// The builder is freed and cannot be reused.
func (b *paramBuilder) build() (C.GO_OSSL_PARAM_PTR, error) {
	b.check()
	param := C.go_openssl_OSSL_PARAM_BLD_to_param(b.bld)
	if param == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_build")
	}
	b.free() // we shouldn't reuse the builder once we've built the params
	return param, nil
}

func (b *paramBuilder) addUtf8String(name *C.char, value *C.char, size C.size_t) {
	b.check()
	if C.go_openssl_OSSL_PARAM_BLD_push_utf8_string(b.bld, name, value, size) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_utf8_string")
	}
}

// addOctetString adds an octet string to the builder.
// The value is pinned and will be unpinned when the builder is freed.
func (b *paramBuilder) addOctetString(name *C.char, value []byte) {
	b.check()
	if len(value) > 0 {
		b.pinner.Pin(&value[0])
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_octet_string(b.bld, name, unsafe.Pointer(sbase(value)), C.size_t(len(value))) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_octet_string")
	}
}

func (b *paramBuilder) addBN(name *C.char, value C.GO_BIGNUM_PTR) {
	b.check()
	if C.go_openssl_OSSL_PARAM_BLD_push_BN(b.bld, name, value) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_BN")
	}
}
