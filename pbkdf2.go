//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"hash"
)

func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	md := hashToMD(hashFuncHash(h))
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
