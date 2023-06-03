//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"hash"
	"io"
	"runtime"
	"unsafe"
)

func SupportsHKDF() bool {
	return vMajor > 1 ||
		(vMajor >= 1 && vMinor > 1) ||
		(vMajor >= 1 && vMinor >= 1 && vPatch >= 1)
}

func newHKDF(h func() hash.Hash, mode C.int) (*hkdf, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}

	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(C.GO_EVP_PKEY_HKDF, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new_id")
	}
	defer func() {
		C.go_openssl_EVP_PKEY_CTX_free(ctx)
	}()

	if C.go_openssl_EVP_PKEY_derive_init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	switch vMajor {
	case 3:
		if C.go_openssl_EVP_PKEY_CTX_set_hkdf_mode(ctx, mode) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set_hkdf_mode")
		}
		if C.go_openssl_EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set_hkdf_md")
		}
	case 1:
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_HKDF_MODE,
			C.int(mode), nil) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set_hkdf_mode")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_HKDF_MD,
			0, unsafe.Pointer(md)) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set_hkdf_md")
		}
	}

	c := &hkdf{ctx: ctx}
	ctx = nil

	runtime.SetFinalizer(c, (*hkdf).finalize)

	return c, nil
}

type hkdf struct {
	ctx C.GO_EVP_PKEY_CTX_PTR
}

func (c *hkdf) finalize() {
	if c.ctx != nil {
		C.go_openssl_EVP_PKEY_CTX_free(c.ctx)
	}
}

func (c *hkdf) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(c)

	outLen := C.size_t(len(p))
	if C.go_openssl_EVP_PKEY_derive(c.ctx, base(p), &outLen) != 1 {
		return 0, newOpenSSLError("EVP_PKEY_derive")
	}
	return int(outLen), nil
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	c, err := newHKDF(h, C.GO_EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
	if err != nil {
		return nil, err
	}
	switch vMajor {
	case 3:
		if C.go_openssl_EVP_PKEY_CTX_set1_hkdf_key(c.ctx,
			base(secret), C.int(len(secret))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key")
		}
		if C.go_openssl_EVP_PKEY_CTX_set1_hkdf_salt(c.ctx,
			base(salt), C.int(len(salt))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_salt")
		}
	case 1:
		if C.go_openssl_EVP_PKEY_CTX_ctrl(c.ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_HKDF_KEY,
			C.int(len(secret)), unsafe.Pointer(base(secret))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(c.ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_HKDF_SALT,
			C.int(len(salt)), unsafe.Pointer(base(salt))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_salt")
		}
	}
	var outLen C.size_t
	if C.go_openssl_EVP_PKEY_derive(c.ctx, nil, &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	out := make([]byte, outLen)
	if C.go_openssl_EVP_PKEY_derive(c.ctx, base(out), &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive")
	}
	return out[:outLen], nil
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	c, err := newHKDF(h, C.GO_EVP_KDF_HKDF_MODE_EXPAND_ONLY)
	if err != nil {
		return nil, err
	}
	switch vMajor {
	case 3:
		if C.go_openssl_EVP_PKEY_CTX_set1_hkdf_key(c.ctx,
			base(pseudorandomKey), C.int(len(pseudorandomKey))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key")
		}
		if C.go_openssl_EVP_PKEY_CTX_add1_hkdf_info(c.ctx,
			base(info), C.int(len(info))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_add1_hkdf_info")
		}
	case 1:
		if C.go_openssl_EVP_PKEY_CTX_ctrl(c.ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_HKDF_KEY,
			C.int(len(pseudorandomKey)), unsafe.Pointer(base(pseudorandomKey))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(c.ctx, -1, C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_HKDF_INFO,
			C.int(len(info)), unsafe.Pointer(base(info))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_add1_hkdf_info")
		}
	}
	return c, nil
}
