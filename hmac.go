//go:build !cmd_go_bootstrap

package openssl

import "C"
import (
	"hash"
	"runtime"
	"sync"
	"unsafe"
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
		key = make([]byte, _EVP_MAX_MD_SIZE)
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
	ctx _HMAC_CTX_PTR
}

// hmacCtx3 is used for OpenSSL 3.
type hmacCtx3 struct {
	ctx _EVP_MAC_CTX_PTR
	key []byte // only set for OpenSSL 3.0.0, 3.0.1, and 3.0.2.
}

type opensslHMAC struct {
	ctx1      hmacCtx1
	ctx3      hmacCtx3
	size      int
	blockSize int
	sum       []byte
}

func newHMAC1(key []byte, md _EVP_MD_PTR) hmacCtx1 {
	ctx := go_openssl_HMAC_CTX_new()
	if ctx == nil {
		panic("openssl: EVP_MAC_CTX_new failed")
	}
	if go_openssl_HMAC_Init_ex(ctx, unsafe.Pointer(&key[0]), int32(len(key)), md, nil) == 0 {
		panic(newOpenSSLError("HMAC_Init_ex failed"))
	}
	return hmacCtx1{ctx}
}

var hmacDigestsSupported sync.Map
var fetchHMAC3 = sync.OnceValue(func() _EVP_MAC_PTR {
	mac := go_openssl_EVP_MAC_fetch(nil, _OSSL_MAC_NAME_HMAC.ptr(), nil)
	if mac == nil {
		panic("openssl: HMAC not supported")
	}
	return mac
})

func buildHMAC3Params(md _EVP_MD_PTR) (_OSSL_PARAM_PTR, error) {
	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()
	bld.addUTF8String(_OSSL_MAC_PARAM_DIGEST, go_openssl_EVP_MD_get0_name(md), 0)
	return bld.build()
}

func isHMAC3DigestSupported(md _EVP_MD_PTR) bool {
	nid := go_openssl_EVP_MD_get_type(md)
	if v, ok := hmacDigestsSupported.Load(nid); ok {
		return v.(bool)
	}
	ctx := go_openssl_EVP_MAC_CTX_new(fetchHMAC3())
	if ctx == nil {
		panic(newOpenSSLError("EVP_MAC_CTX_new"))
	}
	defer go_openssl_EVP_MAC_CTX_free(ctx)

	params, err := buildHMAC3Params(md)
	if err != nil {
		panic(err)
	}
	defer go_openssl_OSSL_PARAM_free(params)

	supported := go_openssl_EVP_MAC_CTX_set_params(ctx, params) != 0
	hmacDigestsSupported.Store(nid, supported)
	return supported
}

func newHMAC3(key []byte, md _EVP_MD_PTR) hmacCtx3 {
	if !isHMAC3DigestSupported(md) {
		// The digest is not supported by the HMAC provider.
		// Don't panic here so the Go standard library to
		// fall back to the Go implementation.
		// See https://github.com/golang-fips/openssl/issues/153.
		return hmacCtx3{}
	}
	params, err := buildHMAC3Params(md)
	if err != nil {
		panic(err)
	}
	defer go_openssl_OSSL_PARAM_free(params)

	ctx := go_openssl_EVP_MAC_CTX_new(fetchHMAC3())
	if ctx == nil {
		panic(newOpenSSLError("EVP_MAC_CTX_new"))
	}

	if go_openssl_EVP_MAC_init(ctx, base(key), len(key), params) == 0 {
		go_openssl_EVP_MAC_CTX_free(ctx)
		panic(newOpenSSLError("EVP_MAC_init"))
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
		if go_openssl_HMAC_Init_ex(h.ctx1.ctx, nil, 0, nil, nil) == 0 {
			panic(newOpenSSLError("HMAC_Init_ex failed"))
		}
	case 3:
		if go_openssl_EVP_MAC_init(h.ctx3.ctx, base(h.ctx3.key), len(h.ctx3.key), nil) == 0 {
			panic(newOpenSSLError("EVP_MAC_init failed"))
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
		go_openssl_HMAC_CTX_free(h.ctx1.ctx)
	case 3:
		go_openssl_EVP_MAC_CTX_free(h.ctx3.ctx)
	default:
		panic(errUnsupportedVersion())
	}
}

func (h *opensslHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		switch vMajor {
		case 1:
			go_openssl_HMAC_Update(h.ctx1.ctx, base(p), len(p))
		case 3:
			go_openssl_EVP_MAC_update(h.ctx3.ctx, base(p), len(p))
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
		ctx2 := go_openssl_HMAC_CTX_new()
		if ctx2 == nil {
			panic("openssl: HMAC_CTX_new failed")
		}
		defer go_openssl_HMAC_CTX_free(ctx2)
		if go_openssl_HMAC_CTX_copy(ctx2, h.ctx1.ctx) == 0 {
			panic("openssl: HMAC_CTX_copy failed")
		}
		go_openssl_HMAC_Final(ctx2, base(h.sum), nil)
	case 3:
		ctx2 := go_openssl_EVP_MAC_CTX_dup(h.ctx3.ctx)
		if ctx2 == nil {
			panic("openssl: EVP_MAC_CTX_dup failed")
		}
		defer go_openssl_EVP_MAC_CTX_free(ctx2)
		go_openssl_EVP_MAC_final(ctx2, base(h.sum), nil, len(h.sum))
	default:
		panic(errUnsupportedVersion())
	}
	return append(in, h.sum...)
}
