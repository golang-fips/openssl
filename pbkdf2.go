//go:build linux && !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"hash"
)

func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	md := hashToMD(h())
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}
	out := make([]byte, keyLen)
	ok := C.go_openssl_PKCS5_PBKDF2_HMAC(sbase(password), C.int(len(password)), base(salt), C.int(len(salt)), C.int(iter), md, C.int(keyLen), base(out))
	if ok != 1 {
		return nil, newOpenSSLError("PKCS5_PBKDF2_HMAC")
	}
	return out, nil
}
