//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"runtime"
	"unsafe"
)

type bnParam struct {
	value   C.GO_BIGNUM_PTR
	private bool
}

// paramBuilder is a helper for building OSSL_PARAMs.
// If an error occurs when adding a new parameter,
// subsequent calls to add parameters are ignored
// and build() will return the error.
type paramBuilder struct {
	bld      C.GO_OSSL_PARAM_BLD_PTR
	pinner   runtime.Pinner
	bnToFree []bnParam

	err error
}

// newParamBuilder creates a new paramBuilder.
func newParamBuilder() (*paramBuilder, error) {
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	pb := &paramBuilder{
		bld:      bld,
		bnToFree: make([]bnParam, 0, 8), // the maximum known number of BIGNUMs to free are 8 for RSA
	}
	runtime.SetFinalizer(pb, (*paramBuilder).finalize)
	return pb, nil
}

// finalize frees the builder.
func (b *paramBuilder) finalize() {
	if b.bld != nil {
		b.pinner.Unpin()
		for _, bn := range b.bnToFree {
			if bn.private {
				C.go_openssl_BN_clear_free(bn.value)
			} else {
				C.go_openssl_BN_free(bn.value)
			}
		}
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
func (b *paramBuilder) addUTF8String(name cString, value *C.char, size C.size_t) {
	if !b.check() {
		return
	}
	// OSSL_PARAM_BLD_push_utf8_string calculates the size if it is zero.
	if C.go_openssl_OSSL_PARAM_BLD_push_utf8_string(b.bld, name.ptr(), value, size) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_utf8_string(" + name.str() + ")")
	}
}

// addOctetString adds an octet string to the builder.
// The value is pinned and will be unpinned when the builder is freed.
func (b *paramBuilder) addOctetString(name cString, value []byte) {
	if !b.check() {
		return
	}
	if len(value) != 0 {
		b.pinner.Pin(&value[0])
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_octet_string(b.bld, name.ptr(), unsafe.Pointer(sbase(value)), C.size_t(len(value))) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_octet_string(" + name.str() + ")")
	}
}

// addInt32 adds an int32 to the builder.
func (b *paramBuilder) addInt32(name cString, value int32) {
	if !b.check() {
		return
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_int32(b.bld, name.ptr(), C.int32_t(value)) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_int32(" + name.str() + ")")
	}
}

// addBN adds a GO_BIGNUM_PTR to the builder.
func (b *paramBuilder) addBN(name cString, value C.GO_BIGNUM_PTR) {
	if !b.check() {
		return
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_BN(b.bld, name.ptr(), value) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_BN(" + name.str() + ")")
	}
}

// addBin adds a byte slice to the builder.
// The slice is converted to a BIGNUM using BN_bin2bn and freed when the builder is finalized.
// If private is true, the BIGNUM will be cleared with BN_clear_free,
// otherwise it will be freed with BN_free.
func (b *paramBuilder) addBin(name cString, value []byte, private bool) {
	if !b.check() {
		return
	}
	if len(value) == 0 {
		// Nothing to do.
		return
	}
	bn := C.go_openssl_BN_bin2bn(base(value), C.int(len(value)), nil)
	if bn == nil {
		b.err = newOpenSSLError("BN_bin2bn")
		return
	}
	b.bnToFree = append(b.bnToFree, bnParam{bn, private})
	b.addBN(name, bn)
}

// addBigInt adds a BigInt to the builder.
// The BigInt is converted using bigToBN to a BIGNUM that is freed when the builder is finalized.
// If private is true, the BIGNUM will be cleared with BN_clear_free,
// otherwise it will be freed with BN_free.
func (b *paramBuilder) addBigInt(name cString, value BigInt, private bool) {
	if !b.check() {
		return
	}
	if len(value) == 0 {
		// Nothing to do.
		return
	}
	bn := bigToBN(value)
	if bn == nil {
		b.err = newOpenSSLError("bigToBN")
		return
	}
	b.bnToFree = append(b.bnToFree, bnParam{bn, private})
	b.addBN(name, bn)
}
