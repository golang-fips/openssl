//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"hash"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

// SupprtHKDF reports whether the current OpenSSL version supports HKDF.
func SupportsHKDF() bool {
	switch vMajor {
	case 1:
		return versionAtOrAbove(1, 1, 1)
	case 3:
		_, err := fetchHKDF3()
		return err == nil
	default:
		panic(errUnsupportedVersion())
	}
}

func newHKDFCtx1(md C.GO_EVP_MD_PTR, mode C.int, secret, salt, pseudorandomKey, info []byte) (ctx C.GO_EVP_PKEY_CTX_PTR, err error) {
	checkMajorVersion(1)

	ctx = C.go_openssl_EVP_PKEY_CTX_new_id(C.GO_EVP_PKEY_HKDF, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new_id")
	}
	defer func() {
		if err != nil {
			C.go_openssl_EVP_PKEY_CTX_free(ctx)
		}
	}()

	if C.go_openssl_EVP_PKEY_derive_init(ctx) != 1 {
		return ctx, newOpenSSLError("EVP_PKEY_derive_init")
	}

	ctrlSlice := func(ctrl int, data []byte) C.int {
		if len(data) == 0 {
			return 1 // No data to set.
		}
		return C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE, C.int(ctrl), C.int(len(data)), unsafe.Pointer(base(data)))
	}

	if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_HKDF_MODE, mode, nil) != 1 {
		return ctx, newOpenSSLError("EVP_PKEY_CTX_set_hkdf_mode")
	}
	if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_HKDF_MD, 0, unsafe.Pointer(md)) != 1 {
		return ctx, newOpenSSLError("EVP_PKEY_CTX_set_hkdf_md")
	}
	if ctrlSlice(C.GO_EVP_PKEY_CTRL_HKDF_KEY, secret) != 1 {
		return ctx, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key")
	}
	if ctrlSlice(C.GO_EVP_PKEY_CTRL_HKDF_SALT, salt) != 1 {
		return ctx, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_salt")
	}
	if ctrlSlice(C.GO_EVP_PKEY_CTRL_HKDF_KEY, pseudorandomKey) != 1 {
		return ctx, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key")
	}
	if ctrlSlice(C.GO_EVP_PKEY_CTRL_HKDF_INFO, info) != 1 {
		return ctx, newOpenSSLError("EVP_PKEY_CTX_add1_hkdf_info")
	}
	return ctx, nil
}

type hkdf1 struct {
	ctx C.GO_EVP_PKEY_CTX_PTR

	hashLen int
	buf     []byte
}

func (c *hkdf1) finalize() {
	if c.ctx != nil {
		C.go_openssl_EVP_PKEY_CTX_free(c.ctx)
	}
}

func (c *hkdf1) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(c)

	// EVP_PKEY_derive doesn't support incremental output, each call
	// derives the key from scratch and returns the requested bytes.
	// To implement io.Reader, we need to ask for len(c.buf) + len(p)
	// bytes and copy the last derived len(p) bytes to p.
	// We use c.buf to know how many bytes we've already derived and
	// to avoid allocating the whole output buffer on each call.
	prevLen := len(c.buf)
	needLen := len(p)
	remains := 255*c.hashLen - prevLen
	// Check whether enough data can be generated.
	if remains < needLen {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	c.buf = append(c.buf, make([]byte, needLen)...)
	outLen := C.size_t(prevLen + needLen)
	if C.go_openssl_EVP_PKEY_derive_wrapper(c.ctx, base(c.buf), outLen).result != 1 {
		return 0, newOpenSSLError("EVP_PKEY_derive")
	}
	n := copy(p, c.buf[prevLen:outLen])
	return n, nil
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	md, err := hashFuncToMD(h)
	if err != nil {
		return nil, err
	}

	switch vMajor {
	case 1:
		ctx, err := newHKDFCtx1(md, C.GO_EVP_KDF_HKDF_MODE_EXTRACT_ONLY, secret, salt, nil, nil)
		if err != nil {
			return nil, err
		}
		defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
		r := C.go_openssl_EVP_PKEY_derive_wrapper(ctx, nil, 0)
		if r.result != 1 {
			return nil, newOpenSSLError("EVP_PKEY_derive_init")
		}
		out := make([]byte, r.keylen)
		if C.go_openssl_EVP_PKEY_derive_wrapper(ctx, base(out), r.keylen).result != 1 {
			return nil, newOpenSSLError("EVP_PKEY_derive")
		}
		return out[:r.keylen], nil
	case 3:
		ctx, err := newHKDFCtx3(md, C.GO_EVP_KDF_HKDF_MODE_EXTRACT_ONLY, secret, salt, nil, nil)
		if err != nil {
			return nil, err
		}
		defer C.go_openssl_EVP_KDF_CTX_free(ctx)
		out := make([]byte, C.go_openssl_EVP_KDF_CTX_get_kdf_size(ctx))
		if C.go_openssl_EVP_KDF_derive(ctx, base(out), C.size_t(len(out)), nil) != 1 {
			return nil, newOpenSSLError("EVP_KDF_derive")
		}
		return out, nil
	default:
		panic(errUnsupportedVersion())
	}
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	md, err := hashFuncToMD(h)
	if err != nil {
		return nil, err
	}

	switch vMajor {
	case 1:
		ctx, err := newHKDFCtx1(md, C.GO_EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		c := &hkdf1{ctx: ctx, hashLen: int(C.go_openssl_EVP_MD_get_size(md))}
		runtime.SetFinalizer(c, (*hkdf1).finalize)
		return c, nil
	case 3:
		ctx, err := newHKDFCtx3(md, C.GO_EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		c := &hkdf3{ctx: ctx, hashLen: int(C.go_openssl_EVP_MD_get_size(md))}
		runtime.SetFinalizer(c, (*hkdf3).finalize)
		return c, nil
	default:
		panic(errUnsupportedVersion())
	}
}

type hkdf3 struct {
	ctx C.GO_EVP_KDF_CTX_PTR

	hashLen int
	buf     []byte
}

func (c *hkdf3) finalize() {
	if c.ctx != nil {
		C.go_openssl_EVP_KDF_CTX_free(c.ctx)
	}
}

// fetchHKDF3 fetches the HKDF algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchHKDF3 = sync.OnceValues(func() (C.GO_EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	name := C.CString("HKDF")
	kdf := C.go_openssl_EVP_KDF_fetch(nil, name, nil)
	C.free(unsafe.Pointer(name))
	if kdf == nil {
		return nil, newOpenSSLError("EVP_KDF_fetch")
	}
	return kdf, nil
})

// newHKDFCtx3 implements HKDF for OpenSSL 3 using the EVP_KDF API.
func newHKDFCtx3(md C.GO_EVP_MD_PTR, mode C.int, secret, salt, pseudorandomKey, info []byte) (_ C.GO_EVP_KDF_CTX_PTR, err error) {
	checkMajorVersion(3)

	kdf, err := fetchHKDF3()
	if err != nil {
		return nil, err
	}
	ctx := C.go_openssl_EVP_KDF_CTX_new(kdf)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_KDF_CTX_new")
	}
	defer func() {
		if err != nil {
			C.go_openssl_EVP_KDF_CTX_free(ctx)
		}
	}()

	bld, err := newParamBuilder()
	if err != nil {
		return ctx, err
	}
	bld.addUTF8String(_OSSL_KDF_PARAM_DIGEST, C.go_openssl_EVP_MD_get0_name(md), 0)
	bld.addInt32(_OSSL_KDF_PARAM_MODE, int32(mode))
	if len(secret) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_KEY, secret)
	}
	if len(salt) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_SALT, salt)
	}
	if len(pseudorandomKey) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_KEY, pseudorandomKey)
	}
	if len(info) > 0 {
		bld.addOctetString(_OSSL_KDF_PARAM_INFO, info)
	}
	params, err := bld.build()
	if err != nil {
		return ctx, err
	}
	defer C.go_openssl_OSSL_PARAM_free(params)

	if C.go_openssl_EVP_KDF_CTX_set_params(ctx, params) != 1 {
		return ctx, newOpenSSLError("EVP_KDF_CTX_set_params")
	}
	return ctx, nil
}

func (c *hkdf3) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(c)

	// EVP_KDF_derive doesn't support incremental output, each call
	// derives the key from scratch and returns the requested bytes.
	// To implement io.Reader, we need to ask for len(c.buf) + len(p)
	// bytes and copy the last derived len(p) bytes to p.
	// We use c.buf to know how many bytes we've already derived and
	// to avoid allocating the whole output buffer on each call.
	prevLen := len(c.buf)
	needLen := len(p)
	remains := 255*c.hashLen - prevLen
	// Check whether enough data can be generated.
	if remains < needLen {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	c.buf = append(c.buf, make([]byte, needLen)...)
	outLen := C.size_t(prevLen + needLen)
	if C.go_openssl_EVP_KDF_derive(c.ctx, base(c.buf), outLen, nil) != 1 {
		return 0, newOpenSSLError("EVP_KDF_derive")
	}
	n := copy(p, c.buf[prevLen:outLen])
	return n, nil
}
