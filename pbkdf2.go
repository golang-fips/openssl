//go:build !cmd_go_bootstrap

package openssl

import "C"
import (
	"errors"
	"hash"
	"sync"
)

// SupportsPBKDF2 reports whether the current OpenSSL version supports PBKDF2.
func SupportsPBKDF2() bool {
	switch vMajor {
	case 1:
		return true
	case 3:
		_, err := fetchPBKDF2()
		return err == nil
	default:
		panic(errUnsupportedVersion())
	}
}

// fetchPBKDF2 fetches the PBKDF2 algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchPBKDF2 = sync.OnceValues(func() (_EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	kdf := go_openssl_EVP_KDF_fetch(nil, _OSSL_KDF_NAME_PBKDF2.ptr(), nil)
	if kdf == nil {
		return nil, newOpenSSLError("EVP_KDF_fetch")
	}
	return kdf, nil
})

func PBKDF2(password, salt []byte, iter, keyLen int, fh func() hash.Hash) ([]byte, error) {
	h, err := hashFuncHash(fh)
	if err != nil {
		return nil, err
	}
	md := hashToMD(h)
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}
	out := make([]byte, keyLen)
	ok := go_openssl_PKCS5_PBKDF2_HMAC(base(password), int32(len(password)), base(salt), int32(len(salt)), int32(iter), md, int32(keyLen), base(out))
	if ok != 1 {
		return nil, newOpenSSLError("PKCS5_PBKDF2_HMAC")
	}
	return out, nil
}
