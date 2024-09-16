//go:build !cmd_go_bootstrap

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

// SupprtHKDF reports whether the current OpenSSL version supports HKDF.
func SupportsHKDF() bool {
	switch vMajor {
	case 1:
		return versionAtOrAbove(1, 1, 1)
	case 3:
		// Some OpenSSL 3 providers don't support HKDF or don't support it via
		// the EVP_PKEY API, which is the one we use.
		// See https://github.com/golang-fips/openssl/issues/189.
		ctx := C.go_openssl_EVP_PKEY_CTX_new_id(C.GO_EVP_PKEY_HKDF, nil)
		if ctx == nil {
			return false
		}
		C.go_openssl_EVP_PKEY_CTX_free(ctx)
		return true
	default:
		panic(errUnsupportedVersion())
	}
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

	c := &hkdf{ctx: ctx, hashLen: ch.Size()}
	ctx = nil

	runtime.SetFinalizer(c, (*hkdf).finalize)

	return c, nil
}

type hkdf struct {
	ctx C.GO_EVP_PKEY_CTX_PTR

	hashLen int
	buf     []byte
}

func (c *hkdf) finalize() {
	if c.ctx != nil {
		C.go_openssl_EVP_PKEY_CTX_free(c.ctx)
	}
}

func (c *hkdf) Read(p []byte) (int, error) {
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
	r := C.go_openssl_EVP_PKEY_derive_wrapper(c.ctx, nil, 0)
	if r.result != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	out := make([]byte, r.keylen)
	if C.go_openssl_EVP_PKEY_derive_wrapper(c.ctx, base(out), r.keylen).result != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive")
	}
	return out[:r.keylen], nil
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
