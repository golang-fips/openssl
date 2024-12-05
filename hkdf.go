//go:build !cmd_go_bootstrap && cgo

package openssl

import (
	"errors"
	"hash"
	"io"
	"runtime"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
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

func newHKDFCtx1(md ossl.EVP_MD_PTR, mode int, secret, salt, pseudorandomKey, info []byte) (ctx ossl.EVP_PKEY_CTX_PTR, err error) {
	checkMajorVersion(1)

	ctx, err = ossl.EVP_PKEY_CTX_new_id(ossl.EVP_PKEY_HKDF, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ossl.EVP_PKEY_CTX_free(ctx)
		}
	}()

	if err := ossl.EVP_PKEY_derive_init(ctx); err != nil {
		return ctx, err
	}

	ctrlSlice := func(ctrl int, data []byte) error {
		if len(data) == 0 {
			return nil // No data to set.
		}
		return ossl.EVP_PKEY_CTX_ctrl(ctx, -1, ossl.GO1_EVP_PKEY_OP_DERIVE, int32(ctrl), int32(len(data)), unsafe.Pointer(base(data)))
	}

	if err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1, ossl.GO1_EVP_PKEY_OP_DERIVE, ossl.EVP_PKEY_CTRL_HKDF_MODE, int32(mode), nil); err != nil {
		return ctx, err
	}
	if err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1, ossl.GO1_EVP_PKEY_OP_DERIVE, ossl.EVP_PKEY_CTRL_HKDF_MD, 0, unsafe.Pointer(md)); err != nil {
		return ctx, err
	}
	if err := ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_KEY, secret); err != nil {
		return ctx, err
	}
	if err := ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_SALT, salt); err != nil {
		return ctx, err
	}
	if err := ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_KEY, pseudorandomKey); err != nil {
		return ctx, err
	}
	if err := ctrlSlice(ossl.EVP_PKEY_CTRL_HKDF_INFO, info); err != nil {
		return ctx, err
	}
	return ctx, nil
}

type hkdf1 struct {
	ctx ossl.EVP_PKEY_CTX_PTR

	hashLen int
	buf     []byte
}

func (c *hkdf1) finalize() {
	if c.ctx != nil {
		ossl.EVP_PKEY_CTX_free(c.ctx)
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
	outLen := prevLen + needLen
	if _, err := ossl.EVP_PKEY_derive_wrapper(c.ctx, base(c.buf), outLen); err != nil {
		return 0, err
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
		ctx, err := newHKDFCtx1(md, ossl.EVP_KDF_HKDF_MODE_EXTRACT_ONLY, secret, salt, nil, nil)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_PKEY_CTX_free(ctx)
		keyLength, err := ossl.EVP_PKEY_derive_wrapper(ctx, nil, 0)
		if err != nil {
			return nil, err
		}
		out := make([]byte, keyLength)
		if _, err := ossl.EVP_PKEY_derive_wrapper(ctx, base(out), keyLength); err != nil {
			return nil, err
		}
		return out, nil
	case 3:
		ctx, err := newHKDFCtx3(md, ossl.EVP_KDF_HKDF_MODE_EXTRACT_ONLY, secret, salt, nil, nil)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_KDF_CTX_free(ctx)
		size, err := ossl.EVP_KDF_CTX_get_kdf_size(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]byte, size)
		if err := ossl.EVP_KDF_derive(ctx, base(out), len(out), nil); err != nil {
			return nil, err
		}
		return out, nil
	default:
		panic(errUnsupportedVersion())
	}
}

// ExpandHKDFOneShot derives a key from the given hash, key, and optional context info.
func ExpandHKDFOneShot(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	md, err := hashFuncToMD(h)
	if err != nil {
		return nil, err
	}

	out := make([]byte, keyLength)
	switch vMajor {
	case 1:
		ctx, err := newHKDFCtx1(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_PKEY_CTX_free(ctx)
		if _, err := ossl.EVP_PKEY_derive_wrapper(ctx, base(out), keyLength); err != nil {
			return nil, err
		}
	case 3:
		ctx, err := newHKDFCtx3(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_KDF_CTX_free(ctx)
		if err := ossl.EVP_KDF_derive(ctx, base(out), keyLength, nil); err != nil {
			return nil, err
		}
	default:
		panic(errUnsupportedVersion())
	}
	return out, nil
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
		ctx, err := newHKDFCtx1(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		c := &hkdf1{ctx: ctx, hashLen: int(ossl.EVP_MD_get_size(md))}
		runtime.SetFinalizer(c, (*hkdf1).finalize)
		return c, nil
	case 3:
		ctx, err := newHKDFCtx3(md, ossl.EVP_KDF_HKDF_MODE_EXPAND_ONLY, nil, nil, pseudorandomKey, info)
		if err != nil {
			return nil, err
		}
		c := &hkdf3{ctx: ctx, hashLen: int(ossl.EVP_MD_get_size(md))}
		runtime.SetFinalizer(c, (*hkdf3).finalize)
		return c, nil
	default:
		panic(errUnsupportedVersion())
	}
}

type hkdf3 struct {
	ctx ossl.EVP_KDF_CTX_PTR

	hashLen int
	buf     []byte
}

func (c *hkdf3) finalize() {
	if c.ctx != nil {
		ossl.EVP_KDF_CTX_free(c.ctx)
	}
}

// fetchHKDF3 fetches the HKDF algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchHKDF3 = sync.OnceValues(func() (ossl.EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	kdf, err := ossl.EVP_KDF_fetch(nil, cStringData(ossl.OSSL_KDF_NAME_HKDF), nil)
	if err != nil {
		return nil, err
	}
	return kdf, nil
})

// newHKDFCtx3 implements HKDF for OpenSSL 3 using the EVP_KDF API.
func newHKDFCtx3(md ossl.EVP_MD_PTR, mode int, secret, salt, pseudorandomKey, info []byte) (_ ossl.EVP_KDF_CTX_PTR, err error) {
	checkMajorVersion(3)

	kdf, err := fetchHKDF3()
	if err != nil {
		return nil, err
	}
	ctx, err := ossl.EVP_KDF_CTX_new(kdf)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ossl.EVP_KDF_CTX_free(ctx)
		}
	}()

	bld, err := newParamBuilder()
	if err != nil {
		return ctx, err
	}
	bld.addUTF8String(ossl.OSSL_KDF_PARAM_DIGEST, ossl.EVP_MD_get0_name(md), 0)
	bld.addInt32(ossl.OSSL_KDF_PARAM_MODE, int32(mode))
	if len(secret) > 0 {
		bld.addOctetString(ossl.OSSL_KDF_PARAM_KEY, secret)
	}
	if len(salt) > 0 {
		bld.addOctetString(ossl.OSSL_KDF_PARAM_SALT, salt)
	}
	if len(pseudorandomKey) > 0 {
		bld.addOctetString(ossl.OSSL_KDF_PARAM_KEY, pseudorandomKey)
	}
	if len(info) > 0 {
		bld.addOctetString(ossl.OSSL_KDF_PARAM_INFO, info)
	}
	params, err := bld.build()
	if err != nil {
		return ctx, err
	}
	defer ossl.OSSL_PARAM_free(params)

	if err := ossl.EVP_KDF_CTX_set_params(ctx, params); err != nil {
		return ctx, err
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
	outLen := prevLen + needLen
	if err := ossl.EVP_KDF_derive(c.ctx, base(c.buf), outLen, nil); err != nil {
		return 0, err
	}
	n := copy(p, c.buf[prevLen:outLen])
	return n, nil
}
