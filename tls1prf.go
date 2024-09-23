//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"sync"
	"unsafe"
)

func SupportsTLS1PRF() bool {
	switch vMajor {
	case 1:
		return vMinor >= 1
	case 3:
		_, err := fetchTLS1PRF()
		return err == nil
	default:
		panic(errUnsupportedVersion())
	}
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
		md = hashToMD(h())
	}
	if md == nil {
		return errors.New("unsupported hash function")
	}

	switch vMajor {
	case 1:
		return tls1PRF1(result, secret, label, seed, md)
	case 3:
		return tls1PRF3(result, secret, label, seed, md)
	default:
		return errUnsupportedVersion()
	}
}

// tls1PRF1 implements TLS1PRF for OpenSSL 1 using the EVP_PKEY API.
func tls1PRF1(result, secret, label, seed []byte, md C.GO_EVP_MD_PTR) error {
	checkMajorVersion(1)

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

// fetchTLS1PRF fetches the TLS1-PRF KDF algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchTLS1PRF = sync.OnceValues(func() (C.GO_EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	name := C.CString("TLS1-PRF")
	kdf := C.go_openssl_EVP_KDF_fetch(nil, name, nil)
	C.free(unsafe.Pointer(name))
	if kdf == nil {
		return nil, newOpenSSLError("EVP_KDF_fetch")
	}
	return kdf, nil
})

// tls1PRF3 implements TLS1PRF for OpenSSL 3 using the EVP_KDF API.
func tls1PRF3(result, secret, label, seed []byte, md C.GO_EVP_MD_PTR) error {
	checkMajorVersion(3)

	kdf, err := fetchTLS1PRF()
	if err != nil {
		return err
	}
	ctx := C.go_openssl_EVP_KDF_CTX_new(kdf)
	if ctx == nil {
		return newOpenSSLError("EVP_KDF_CTX_new")
	}
	defer C.go_openssl_EVP_KDF_CTX_free(ctx)

	bld, err := newParamBuilder()
	if err != nil {
		return err
	}
	bld.addUTF8String(_OSSL_KDF_PARAM_DIGEST, C.go_openssl_EVP_MD_get0_name(md), 0)
	bld.addOctetString(_OSSL_KDF_PARAM_SECRET, secret)
	bld.addOctetString(_OSSL_KDF_PARAM_SEED, label)
	bld.addOctetString(_OSSL_KDF_PARAM_SEED, seed)
	params, err := bld.build()
	if err != nil {
		return err
	}
	defer C.go_openssl_OSSL_PARAM_free(params)

	if C.go_openssl_EVP_KDF_derive(ctx, base(result), C.size_t(len(result)), params) != 1 {
		return newOpenSSLError("EVP_KDF_derive")
	}
	return nil
}
