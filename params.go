//go:build !cmd_go_bootstrap && cgo

package openssl

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

type bnParam struct {
	value   ossl.BIGNUM_PTR
	private bool
}

// paramBuilder is a helper for building OSSL_PARAMs.
// If an error occurs when adding a new parameter,
// subsequent calls to add parameters are ignored
// and build() will return the error.
type paramBuilder struct {
	bld      ossl.OSSL_PARAM_BLD_PTR
	pinner   runtime.Pinner
	bnToFree []bnParam

	err error
}

// newParamBuilder creates a new paramBuilder.
func newParamBuilder() (*paramBuilder, error) {
	bld, err := ossl.OSSL_PARAM_BLD_new()
	if err != nil {
		return nil, err
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
				ossl.BN_clear_free(bn.value)
			} else {
				ossl.BN_free(bn.value)
			}
		}
		ossl.OSSL_PARAM_BLD_free(b.bld)
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
func (b *paramBuilder) build() (ossl.OSSL_PARAM_PTR, error) {
	defer b.finalize()
	if !b.check() {
		return nil, b.err
	}
	param, err := ossl.OSSL_PARAM_BLD_to_param(b.bld)
	if err != nil {
		return nil, err
	}
	return param, nil
}

// addUTF8String adds a NUL-terminated UTF-8 string to the builder.
// size should not include the terminating NUL byte. If size is zero, then it will be calculated.
func (b *paramBuilder) addUTF8String(name string, value *byte, size int) {
	if !b.check() {
		return
	}
	// OSSL_PARAM_BLD_push_utf8_string calculates the size if it is zero.
	b.err = ossl.OSSL_PARAM_BLD_push_utf8_string(b.bld, cStringData(name), value, size)
}

// addOctetString adds an octet string to the builder.
// The value is pinned and will be unpinned when the builder is freed.
func (b *paramBuilder) addOctetString(name string, value []byte) {
	if !b.check() {
		return
	}
	if len(value) != 0 {
		b.pinner.Pin(&value[0])
	}
	b.err = ossl.OSSL_PARAM_BLD_push_octet_string(b.bld, cStringData(name), unsafe.Pointer(base(value)), len(value))
}

// addInt32 adds an int32 to the builder.
func (b *paramBuilder) addInt32(name string, value int32) {
	if !b.check() {
		return
	}
	b.err = ossl.OSSL_PARAM_BLD_push_int32(b.bld, cStringData(name), value)
}

// addBN adds a GO_BIGNUM_PTR to the builder.
func (b *paramBuilder) addBN(name string, value ossl.BIGNUM_PTR) {
	if !b.check() {
		return
	}
	b.err = ossl.OSSL_PARAM_BLD_push_BN(b.bld, cStringData(name), value)
}

// addBin adds a byte slice to the builder.
// The slice is converted to a BIGNUM using BN_bin2bn and freed when the builder is finalized.
// If private is true, the BIGNUM will be cleared with BN_clear_free,
// otherwise it will be freed with BN_free.
func (b *paramBuilder) addBin(name string, value []byte, private bool) {
	if !b.check() {
		return
	}
	if len(value) == 0 {
		// Nothing to do.
		return
	}
	bn, err := ossl.BN_bin2bn(base(value), int32(len(value)), nil)
	if err != nil {
		b.err = err
		return
	}
	b.bnToFree = append(b.bnToFree, bnParam{bn, private})
	b.addBN(name, bn)
}

// addBigInt adds a BigInt to the builder.
// The BigInt is converted using bigToBN to a BIGNUM that is freed when the builder is finalized.
// If private is true, the BIGNUM will be cleared with BN_clear_free,
// otherwise it will be freed with BN_free.
func (b *paramBuilder) addBigInt(name string, value BigInt, private bool) {
	if !b.check() {
		return
	}
	if len(value) == 0 {
		// Nothing to do.
		return
	}
	bn := bigToBN(value)
	if bn == nil {
		b.err = errors.New("bigToBN")
		return
	}
	b.bnToFree = append(b.bnToFree, bnParam{bn, private})
	b.addBN(name, bn)
}

func getBnParam(pkey ossl.EVP_PKEY_PTR, name string, bn *ossl.BIGNUM_PTR) error {
	return ossl.EVP_PKEY_get_bn_param(pkey, cStringData(name), bn)
}
