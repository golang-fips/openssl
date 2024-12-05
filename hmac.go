//go:build !cmd_go_bootstrap && cgo

package openssl

import (
	"hash"
	"runtime"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// NewHMAC returns a new HMAC using OpenSSL.
// The function h must return a hash implemented by
// OpenSSL (for example, h could be openssl.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(fh func() hash.Hash, key []byte) hash.Hash {
	h, _ := hashFuncHash(fh)
	md := hashToMD(h)
	if md == nil {
		return nil
	}

	if len(key) == 0 {
		// This is supported in OpenSSL/Standard lib and as such
		// we must support it here. When using HMAC with a null key
		// HMAC_Init will try and reuse the key from the ctx. This is
		// not the behavior previously implemented, so as a workaround
		// we pass an "empty" key.
		key = make([]byte, ossl.EVP_MAX_MD_SIZE)
	}

	hmac := &opensslHMAC{
		size:      h.Size(),
		blockSize: h.BlockSize(),
	}

	switch vMajor {
	case 1:
		ctx := newHMAC1(key, md)
		if ctx.ctx == nil {
			return nil
		}
		hmac.ctx1 = ctx
	case 3:
		ctx := newHMAC3(key, md)
		if ctx.ctx == nil {
			return nil
		}
		hmac.ctx3 = ctx
	default:
		panic(errUnsupportedVersion())
	}
	runtime.SetFinalizer(hmac, (*opensslHMAC).finalize)
	return hmac
}

// hmacCtx3 is used for OpenSSL 1.
type hmacCtx1 struct {
	ctx ossl.HMAC_CTX_PTR
}

// hmacCtx3 is used for OpenSSL 3.
type hmacCtx3 struct {
	ctx ossl.EVP_MAC_CTX_PTR
	key []byte // only set for OpenSSL 3.0.0, 3.0.1, and 3.0.2.
}

type opensslHMAC struct {
	ctx1      hmacCtx1
	ctx3      hmacCtx3
	size      int
	blockSize int
	sum       []byte
}

func newHMAC1(key []byte, md ossl.EVP_MD_PTR) hmacCtx1 {
	ctx := hmacCtxNew()
	if err := ossl.HMAC_Init_ex(ctx, unsafe.Pointer(&key[0]), int32(len(key)), md, nil); err != nil {
		panic(err)
	}
	return hmacCtx1{ctx}
}

var hmacDigestsSupported sync.Map
var fetchHMAC3 = sync.OnceValue(func() ossl.EVP_MAC_PTR {
	mac, err := ossl.EVP_MAC_fetch(nil, cStringData(ossl.OSSL_MAC_NAME_HMAC), nil)
	if err != nil {
		panic("openssl: HMAC not supported")
	}
	return mac
})

func buildHMAC3Params(digest *byte) (ossl.OSSL_PARAM_PTR, error) {
	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()
	bld.addUTF8String(ossl.OSSL_MAC_PARAM_DIGEST, digest, 0)
	return bld.build()
}

func isHMAC3DigestSupported(digest *byte) bool {
	if v, ok := hmacDigestsSupported.Load(digest); ok {
		return v.(bool)
	}
	ctx, err := ossl.EVP_MAC_CTX_new(fetchHMAC3())
	if err != nil {
		panic(err)
	}
	defer ossl.EVP_MAC_CTX_free(ctx)

	params, err := buildHMAC3Params(digest)
	if err != nil {
		panic(err)
	}
	defer ossl.OSSL_PARAM_free(params)

	supported := ossl.EVP_MAC_CTX_set_params(ctx, params) != nil
	hmacDigestsSupported.Store(digest, supported)
	return supported
}

func newHMAC3(key []byte, md ossl.EVP_MD_PTR) hmacCtx3 {
	digest := ossl.EVP_MD_get0_name(md)
	if !isHMAC3DigestSupported(digest) {
		// The digest is not supported by the HMAC provider.
		// Don't panic here so the Go standard library to
		// fall back to the Go implementation.
		// See https://github.com/golang-fips/openssl/issues/153.
		return hmacCtx3{}
	}
	params, err := buildHMAC3Params(digest)
	if err != nil {
		panic(err)
	}
	defer ossl.OSSL_PARAM_free(params)

	ctx, err := ossl.EVP_MAC_CTX_new(fetchHMAC3())
	if err != nil {
		panic(err)
	}

	if err := ossl.EVP_MAC_init(ctx, base(key), len(key), params); err != nil {
		ossl.EVP_MAC_CTX_free(ctx)
		panic(err)
	}
	var hkey []byte
	if vMinor == 0 && vPatch <= 2 {
		// EVP_MAC_init only resets the ctx internal state if a key is passed
		// when using OpenSSL 3.0.0, 3.0.1, and 3.0.2. Save a copy of the key
		// in the context so Reset can use it later. New OpenSSL versions
		// do not have this issue so it isn't necessary to save the key.
		// See https://github.com/openssl/openssl/issues/17811.
		hkey = make([]byte, len(key))
		copy(hkey, key)
	}
	return hmacCtx3{ctx, hkey}
}

func (h *opensslHMAC) Reset() {
	switch vMajor {
	case 1:
		if err := ossl.HMAC_Init_ex(h.ctx1.ctx, nil, 0, nil, nil); err != nil {
			panic(err)
		}
	case 3:
		if err := ossl.EVP_MAC_init(h.ctx3.ctx, base(h.ctx3.key), len(h.ctx3.key), nil); err != nil {
			panic(err)
		}
	default:
		panic(errUnsupportedVersion())
	}

	runtime.KeepAlive(h) // Next line will keep h alive too; just making doubly sure.
	h.sum = nil
}

func (h *opensslHMAC) finalize() {
	switch vMajor {
	case 1:
		hmacCtxFree(h.ctx1.ctx)
	case 3:
		ossl.EVP_MAC_CTX_free(h.ctx3.ctx)
	default:
		panic(errUnsupportedVersion())
	}
}

func (h *opensslHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		switch vMajor {
		case 1:
			ossl.HMAC_Update(h.ctx1.ctx, base(p), len(p))
		case 3:
			ossl.EVP_MAC_update(h.ctx3.ctx, base(p), len(p))
		default:
			panic(errUnsupportedVersion())
		}
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *opensslHMAC) Size() int {
	return h.size
}

func (h *opensslHMAC) BlockSize() int {
	return h.blockSize
}

func (h *opensslHMAC) Sum(in []byte) []byte {
	if h.sum == nil {
		size := h.Size()
		h.sum = make([]byte, size)
	}
	// Make copy of context because Go hash.Hash mandates
	// that Sum has no effect on the underlying stream.
	// In particular it is OK to Sum, then Write more, then Sum again,
	// and the second Sum acts as if the first didn't happen.
	switch vMajor {
	case 1:
		ctx2 := hmacCtxNew()
		defer hmacCtxFree(ctx2)
		if err := ossl.HMAC_CTX_copy(ctx2, h.ctx1.ctx); err != nil {
			panic(err)
		}
		ossl.HMAC_Final(ctx2, base(h.sum), nil)
	case 3:
		ctx2, err := ossl.EVP_MAC_CTX_dup(h.ctx3.ctx)
		if err != nil {
			panic(err)
		}
		defer ossl.EVP_MAC_CTX_free(ctx2)
		ossl.EVP_MAC_final(ctx2, base(h.sum), nil, len(h.sum))
	default:
		panic(errUnsupportedVersion())
	}
	return append(in, h.sum...)
}

func hmacCtxNew() ossl.HMAC_CTX_PTR {
	if vMajor == 1 && vMinor == 0 {
		// 0x120 is the sizeof value when building against OpenSSL 1.0.2 on Ubuntu 16.04.
		ctx := (ossl.HMAC_CTX_PTR)(ossl.CRYPTO_malloc_legacy102(0x120, nil, 0))
		if ctx != nil {
			ossl.HMAC_CTX_init(ctx)
		}
		return ctx
	}
	ctx, err := ossl.HMAC_CTX_new()
	if err != nil {
		panic(err)
	}
	return ctx
}

func hmacCtxFree(ctx ossl.HMAC_CTX_PTR) {
	if vMajor == 1 && vMinor == 0 {
		ossl.HMAC_CTX_cleanup(ctx)
		ossl.CRYPTO_free_legacy102(unsafe.Pointer(ctx))
		return
	}
	ossl.HMAC_CTX_free(ctx)
}
