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

	// PKEY parameters
	_OSSL_PKEY_PARAM_PUB_KEY          = C.CString("pub")
	_OSSL_PKEY_PARAM_PRIV_KEY         = C.CString("priv")
	_OSSL_PKEY_PARAM_GROUP_NAME       = C.CString("group")
	_OSSL_PKEY_PARAM_EC_PUB_X         = C.CString("qx")
	_OSSL_PKEY_PARAM_EC_PUB_Y         = C.CString("qy")
	_OSSL_PKEY_PARAM_FFC_PBITS        = C.CString("pbits")
	_OSSL_PKEY_PARAM_FFC_QBITS        = C.CString("qbits")
	_OSSL_PKEY_PARAM_RSA_N            = C.CString("n")
	_OSSL_PKEY_PARAM_RSA_E            = C.CString("e")
	_OSSL_PKEY_PARAM_RSA_D            = C.CString("d")
	_OSSL_PKEY_PARAM_FFC_P            = C.CString("p")
	_OSSL_PKEY_PARAM_FFC_Q            = C.CString("q")
	_OSSL_PKEY_PARAM_FFC_G            = C.CString("g")
	_OSSL_PKEY_PARAM_RSA_FACTOR1      = C.CString("rsa-factor1")
	_OSSL_PKEY_PARAM_RSA_FACTOR2      = C.CString("rsa-factor2")
	_OSSL_PKEY_PARAM_RSA_EXPONENT1    = C.CString("rsa-exponent1")
	_OSSL_PKEY_PARAM_RSA_EXPONENT2    = C.CString("rsa-exponent2")
	_OSSL_PKEY_PARAM_RSA_COEFFICIENT1 = C.CString("rsa-coefficient1")

	// MAC parameters
	_OSSL_MAC_PARAM_DIGEST = C.CString("digest")
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

// addInt32 adds an int32 to the builder.
func (b *paramBuilder) addInt32(name *C.char, value int32) {
	if !b.check() {
		return
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_int32(b.bld, name, C.int32_t(value)) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_int32(" + C.GoString(name) + ")")
	}
}

// addBN adds a GO_BIGNUM_PTR to the builder.
func (b *paramBuilder) addBN(name *C.char, value C.GO_BIGNUM_PTR) {
	if !b.check() {
		return
	}
	if C.go_openssl_OSSL_PARAM_BLD_push_BN(b.bld, name, value) != 1 {
		b.err = newOpenSSLError("OSSL_PARAM_BLD_push_BN(" + C.GoString(name) + ")")
	}
}

// addBin adds a byte slice to the builder.
// The slice is converted to a BIGNUM using BN_bin2bn and freed when the builder is finalized.
// If private is true, the BIGNUM will be cleared with BN_clear_free,
// otherwise it will be freed with BN_free.
func (b *paramBuilder) addBin(name *C.char, value []byte, private bool) {
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
func (b *paramBuilder) addBigInt(name *C.char, value BigInt, private bool) {
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
