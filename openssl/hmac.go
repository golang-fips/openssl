// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"hash"
	"runtime"
	"unsafe"
)

// hashToMD converts a hash.Hash implementation from this package
// to a BoringCrypto *C.GO_EVP_MD.
func hashToMD(h hash.Hash) *C.GO_EVP_MD {
	switch h.(type) {
	case *sha1Hash:
		return C._goboringcrypto_EVP_sha1()
	case *sha224Hash:
		return C._goboringcrypto_EVP_sha224()
	case *sha256Hash:
		return C._goboringcrypto_EVP_sha256()
	case *sha384Hash:
		return C._goboringcrypto_EVP_sha384()
	case *sha512Hash:
		return C._goboringcrypto_EVP_sha512()
	}
	return nil
}

// cryptoHashToMD converts a crypto.Hash
// to a BoringCrypto *C.GO_EVP_MD.
func cryptoHashToMD(ch crypto.Hash) *C.GO_EVP_MD {
	switch ch {
	case crypto.MD5:
		return C._goboringcrypto_EVP_md5()
	case crypto.MD5SHA1:
		return C._goboringcrypto_EVP_md5_sha1()
	case crypto.SHA1:
		return C._goboringcrypto_EVP_sha1()
	case crypto.SHA224:
		return C._goboringcrypto_EVP_sha224()
	case crypto.SHA256:
		return C._goboringcrypto_EVP_sha256()
	case crypto.SHA384:
		return C._goboringcrypto_EVP_sha384()
	case crypto.SHA512:
		return C._goboringcrypto_EVP_sha512()
	}
	return nil
}

// NewHMAC returns a new HMAC using BoringCrypto.
// The function h must return a hash implemented by
// BoringCrypto (for example, h could be boring.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil
	}

	var hkey []byte
	if key != nil && len(key) > 0 {
		// Note: Could hash down long keys here using EVP_Digest.
		hkey = make([]byte, len(key))
		copy(hkey, key)
	} else {
		// This is supported in BoringSSL/Standard lib and as such
		// we must support it here. When using HMAC with a null key
		// HMAC_Init will try and reuse the key from the ctx. This is
		// not the bahavior previously implemented, so as a workaround
		// we pass an "empty" key.
		hkey = make([]byte, C.EVP_MAX_MD_SIZE)
	}
	k := (*C.uchar)(unsafe.Pointer(&hkey[0]))
	hmac := &boringHMAC{
		md:        md,
		size:      ch.Size(),
		blockSize: ch.BlockSize(),
		ctx:       C._goboringcrypto_HMAC_CTX_new(k, C.int(len(hkey)), md),
	}
	hmac.Reset()
	return hmac
}

type boringHMAC struct {
	md          *C.GO_EVP_MD
	ctx         *C.GO_HMAC_CTX
	size        int
	blockSize   int
	sum         []byte
	needCleanup bool
}

func (h *boringHMAC) Reset() {
	if !h.needCleanup {
		h.needCleanup = true
		// Note: Because of the finalizer, any time h.ctx is passed to cgo,
		// that call must be followed by a call to runtime.KeepAlive(h),
		// to make sure h is not collected (and finalized) before the cgo
		// call returns.
		runtime.SetFinalizer(h, (*boringHMAC).finalize)
	}
	C._goboringcrypto_HMAC_CTX_reset(h.ctx)

	runtime.KeepAlive(h) // Next line will keep h alive too; just making doubly sure.
	h.sum = nil
}

func (h *boringHMAC) finalize() {
	C._goboringcrypto_HMAC_CTX_free(h.ctx)
}

func (h *boringHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		if C._goboringcrypto_HMAC_Update(h.ctx, (*C.uint8_t)(unsafe.Pointer(&p[0])), C.size_t(len(p))) == 0 {
			panic("boringcrypto: HMAC_Update failed")
		}
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *boringHMAC) Size() int {
	return h.size
}

func (h *boringHMAC) BlockSize() int {
	return h.blockSize
}

func (h *boringHMAC) Sum(in []byte) []byte {
	size := h.Size()
	if h.sum == nil {
		h.sum = make([]byte, size)
	}
	if C._goboringcrypto_HMAC_Final(h.ctx, (*C.uint8_t)(unsafe.Pointer(&h.sum[0])), C.uint(size)) == 0 {
		panic("boringcrypto: HMAC_Final failed")
	}
	return append(in, h.sum...)
}
