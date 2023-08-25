//go:build linux && !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"hash"
	"unsafe"
)

func SupportsTLS1PRF() bool {
	return vMajor > 1 ||
		(vMajor >= 1 && vMinor > 1) ||
		(vMajor >= 1 && vMinor >= 1 && vPatch >= 1)
}

func TLS1PRF(secret, label, seed []byte, keyLen int, h func() hash.Hash) ([]byte, error) {
	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}

	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(C.GO_EVP_PKEY_TLS1_PRF, nil)
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
		if C.go_openssl_EVP_PKEY_CTX_set_tls1_prf_md(ctx, md) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set_tls1_prf_md")
		}
		if C.go_openssl_EVP_PKEY_CTX_set1_tls1_prf_secret(ctx,
			base(secret), C.int(len(secret))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_tls1_prf_secret")
		}
		if C.go_openssl_EVP_PKEY_CTX_add1_tls1_prf_seed(ctx,
			base(label), C.int(len(label))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
		if C.go_openssl_EVP_PKEY_CTX_add1_tls1_prf_seed(ctx,
			base(seed), C.int(len(seed))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
	case 1:
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_MD,
			0, unsafe.Pointer(md)) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set_tls1_prf_md")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_SECRET,
			C.int(len(secret)), unsafe.Pointer(base(secret))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_set1_tls1_prf_secret")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_SEED,
			C.int(len(label)), unsafe.Pointer(base(label))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_SEED,
			C.int(len(seed)), unsafe.Pointer(base(seed))) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
	}
	outLen := C.size_t(keyLen)
	out := make([]byte, outLen)
	if C.go_openssl_EVP_PKEY_derive(ctx, base(out), &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive")
	}
	if outLen != C.size_t(keyLen) {
		return nil, errors.New("tls1-prf: entropy limit reached")
	}
	return out[:outLen], nil
}
