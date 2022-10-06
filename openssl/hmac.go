//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"hash"
	"runtime"
	"unsafe"
)

// NewHMAC returns a new HMAC using OpenSSL.
// The function h must return a hash implemented by
// OpenSSL (for example, h could be openssl.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil
	}

	var hkey []byte
	if len(key) > 0 {
		// Note: Could hash down long keys here using EVP_Digest.
		hkey = make([]byte, len(key))
		copy(hkey, key)
	} else {
		// This is supported in OpenSSL/Standard lib and as such
		// we must support it here. When using HMAC with a null key
		// HMAC_Init will try and reuse the key from the ctx. This is
		// not the bahavior previously implemented, so as a workaround
		// we pass an "empty" key.
		hkey = make([]byte, C.GO_EVP_MAX_MD_SIZE)
	}

	return newHMAC(md, ch, hkey)
}

type opensslHMAC struct {
	md        C.GO_EVP_MD_PTR
	ctx       C.GO_HMAC_CTX_PTR
	size      int
	blockSize int
	key       []byte
	sum       []byte
}

func newHMAC(md C.GO_EVP_MD_PTR, h hash.Hash, key []byte) *opensslHMAC {
	hmac := &opensslHMAC{
		md:        md,
		size:      h.Size(),
		blockSize: h.BlockSize(),
		key:       key,
		ctx:       hmacCtxNew(),
	}
	runtime.SetFinalizer(hmac, (*opensslHMAC).finalize)
	hmac.Reset()
	return hmac
}

func (h *opensslHMAC) Reset() {
	hmacCtxReset(h.ctx)

	if C.go_openssl_HMAC_Init_ex(h.ctx, unsafe.Pointer(&h.key[0]), C.int(len(h.key)), h.md, nil) == 0 {
		panic("openssl: HMAC_Init failed")
	}
	if size := C.go_openssl_EVP_MD_get_size(h.md); size != C.int(h.size) {
		println("openssl: HMAC size:", size, "!=", h.size)
		panic("openssl: HMAC size mismatch")
	}
	runtime.KeepAlive(h) // Next line will keep h alive too; just making doubly sure.
	h.sum = nil
}

func (h *opensslHMAC) finalize() {
	hmacCtxFree(h.ctx)
}

func (h *opensslHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		C.go_openssl_HMAC_Update(h.ctx, base(p), C.size_t(len(p)))
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
	ctx2 := hmacCtxNew()
	defer hmacCtxFree(ctx2)
	if C.go_openssl_HMAC_CTX_copy(ctx2, h.ctx) == 0 {
		panic("openssl: HMAC_CTX_copy failed")
	}
	C.go_openssl_HMAC_Final(ctx2, base(h.sum), nil)
	return append(in, h.sum...)
}

func hmacCtxNew() C.GO_HMAC_CTX_PTR {
	if vMajor == 1 && vMinor == 0 {
		// 0x120 is the sizeof value when building against OpenSSL 1.0.2 on Ubuntu 16.04.
		ctx := (C.GO_HMAC_CTX_PTR)(C.malloc(0x120))
		if ctx != nil {
			C.go_openssl_HMAC_CTX_init(ctx)
		}
		return ctx
	}
	return C.go_openssl_HMAC_CTX_new()
}

func hmacCtxReset(ctx C.GO_HMAC_CTX_PTR) {
	if ctx == nil {
		return
	}
	if vMajor == 1 && vMinor == 0 {
		C.go_openssl_HMAC_CTX_cleanup(ctx)
		C.go_openssl_HMAC_CTX_init(ctx)
		return
	}
	C.go_openssl_HMAC_CTX_reset(ctx)
}

func hmacCtxFree(ctx C.GO_HMAC_CTX_PTR) {
	if ctx == nil {
		return
	}
	if vMajor == 1 && vMinor == 0 {
		C.go_openssl_HMAC_CTX_cleanup(ctx)
		C.free(unsafe.Pointer(ctx))
		return
	}
	C.go_openssl_HMAC_CTX_free(ctx)
}
