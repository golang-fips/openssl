//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"hash"
	"sync"
	"unsafe"
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
var fetchPBKDF2 = sync.OnceValues(func() (C.GO_EVP_KDF_PTR, error) {
	checkMajorVersion(3)

	name := C.CString("PBKDF2")
	kdf := C.go_openssl_EVP_KDF_fetch(nil, name, nil)
	C.free(unsafe.Pointer(name))
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
	if len(password) == 0 && vMajor == 1 && vMinor == 0 {
		// x/crypto/pbkdf2 supports empty passwords, but OpenSSL 1.0.2
		// does not. As a workaround, we pass an "empty" password.
		password = make([]byte, C.GO_EVP_MAX_MD_SIZE)
	}
	out := make([]byte, keyLen)
	ok := C.go_openssl_PKCS5_PBKDF2_HMAC(sbase(password), C.int(len(password)), base(salt), C.int(len(salt)), C.int(iter), md, C.int(keyLen), base(out))
	if ok != 1 {
		return nil, newOpenSSLError("PKCS5_PBKDF2_HMAC")
	}
	return out, nil
}
