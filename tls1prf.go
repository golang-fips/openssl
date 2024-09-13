//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"unsafe"
)

func SupportsTLS1PRF() bool {
	return vMajor > 1 ||
		(vMajor >= 1 && vMinor >= 1)
}

// TLS1PRF implements the TLS 1.0/1.1 pseudo-random function if h is nil,
// else it implements the TLS 1.2 pseudo-random function.
// The pseudo-random number will be written to result and will be of length len(result).
func TLS1PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	var md C.GO_EVP_MD_PTR
	if h == nil {
		// TLS 1.0/1.1 PRF doesn't allow to specify the hash function,
		// it always uses MD5SHA1. If h is nil, then assume
		// that the caller wants to use TLS 1.0/1.1 PRF.
		// OpenSSL detects this case by checking if the hash
		// function is MD5SHA1.
		md = cryptoHashToMD(crypto.MD5SHA1)
	} else {
		md = hashToMD(hashFuncHash(h))
	}
	if md == nil {
		return errors.New("unsupported hash function")
	}

	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(C.GO_EVP_PKEY_TLS1_PRF, nil)
	if ctx == nil {
		return newOpenSSLError("EVP_PKEY_CTX_new_id")
	}
	defer func() {
		C.go_openssl_EVP_PKEY_CTX_free(ctx)
	}()

	if C.go_openssl_EVP_PKEY_derive_init(ctx) != 1 {
		return newOpenSSLError("EVP_PKEY_derive_init")
	}
	switch vMajor {
	case 3:
		if C.go_openssl_EVP_PKEY_CTX_set_tls1_prf_md(ctx, md) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_set_tls1_prf_md")
		}
		if C.go_openssl_EVP_PKEY_CTX_set1_tls1_prf_secret(ctx,
			base(secret), C.int(len(secret))) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_set1_tls1_prf_secret")
		}
		if C.go_openssl_EVP_PKEY_CTX_add1_tls1_prf_seed(ctx,
			base(label), C.int(len(label))) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
		if C.go_openssl_EVP_PKEY_CTX_add1_tls1_prf_seed(ctx,
			base(seed), C.int(len(seed))) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
	case 1:
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_MD,
			0, unsafe.Pointer(md)) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_set_tls1_prf_md")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_SECRET,
			C.int(len(secret)), unsafe.Pointer(base(secret))) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_set1_tls1_prf_secret")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_SEED,
			C.int(len(label)), unsafe.Pointer(base(label))) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1,
			C.GO1_EVP_PKEY_OP_DERIVE,
			C.GO_EVP_PKEY_CTRL_TLS_SEED,
			C.int(len(seed)), unsafe.Pointer(base(seed))) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
		}
	}
	outLen := C.size_t(len(result))
	if C.go_openssl_EVP_PKEY_derive_wrapper(ctx, base(result), outLen).result != 1 {
		return newOpenSSLError("EVP_PKEY_derive")
	}
	// The Go standard library expects TLS1PRF to return the requested number of bytes,
	// fail if it doesn't. While there is no known situation where this will happen,
	// EVP_PKEY_derive handles multiple algorithms and there could be a subtle mismatch
	// after more code changes in the future.
	if outLen != C.size_t(len(result)) {
		return errors.New("tls1-prf: derived less bytes than requested")
	}
	return nil
}
