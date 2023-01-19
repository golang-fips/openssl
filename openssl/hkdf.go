// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

// #include "goopenssl.h"
import "C"
import (
	"hash"
	"io"
	"runtime"
)

type hkdf struct {
	ctx *C.GO_EVP_PKEY_CTX
}

func SupportsHKDF() bool {
	return openSSLVersion() >= OPENSSL_VERSION_1_1_1
}

func newHKDF(h func() hash.Hash, mode C.int) (*hkdf, error) {
	if openSSLVersion() < OPENSSL_VERSION_1_1_1 {
		return nil, NewOpenSSLError("HKDF is not supported")
	}

	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil, NewOpenSSLError("Unknown hash algorithm")
	}

	ctx := C._goboringcrypto_EVP_PKEY_CTX_new_id(C.GO_EVP_PKEY_HKDF, nil)
	if ctx == nil {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_new_id failed")
	}
	c := &hkdf{ctx: ctx}
	runtime.SetFinalizer(c, (*hkdf).finalize)
	defer runtime.KeepAlive(c)

	if C._goboringcrypto_EVP_PKEY_derive_init(ctx) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init failed")
	}
	if C._goboringcrypto_EVP_PKEY_CTX_set_hkdf_mode(ctx, mode) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_set_hkdf_mode failed")
	}
	if C._goboringcrypto_EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_set_hkdf_md failed")
	}

	return c, nil
}

func (c *hkdf) finalize() {
	if c.ctx != nil {
		C._goboringcrypto_EVP_PKEY_CTX_free(c.ctx)
	}
}

func (c *hkdf) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(c)

	outLen := C.size_t(len(p))
	if C._goboringcrypto_EVP_PKEY_derive(c.ctx, base(p), &outLen) != 1 {
		return 0, NewOpenSSLError("EVP_PKEY_derive failed")
	}
	return int(outLen), nil
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	c, err := newHKDF(h, C.GO_EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
	if err != nil {
		return nil, err
	}
	if C._goboringcrypto_EVP_PKEY_CTX_set1_hkdf_key(c.ctx, base(secret), C.int(len(secret))) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key failed")
	}
	if C._goboringcrypto_EVP_PKEY_CTX_set1_hkdf_salt(c.ctx, base(salt), C.int(len(salt))) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_set1_hkdf_salt failed")
	}
	var outLen C.size_t
	if C._goboringcrypto_EVP_PKEY_derive(c.ctx, nil, &outLen) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init failed")
	}
	out := make([]byte, outLen)
	if C._goboringcrypto_EVP_PKEY_derive(c.ctx, base(out), &outLen) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive failed")
	}
	return out[:outLen], nil
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	c, err := newHKDF(h, C.GO_EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)
	if err != nil {
		return nil, err
	}
	if C._goboringcrypto_EVP_PKEY_CTX_set1_hkdf_key(c.ctx, base(pseudorandomKey), C.int(len(pseudorandomKey))) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key failed")
	}
	if C._goboringcrypto_EVP_PKEY_CTX_add1_hkdf_info(c.ctx, base(info), C.int(len(info))) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_add1_hkdf_info failed")
	}
	return c, nil
}
