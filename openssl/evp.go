package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"hash"
)

// hashToMD converts a hash.Hash implementation from this package to a GO_EVP_MD_PTR.
func hashToMD(h hash.Hash) C.GO_EVP_MD_PTR {
	switch h.(type) {
	case *sha1Hash:
		return C.go_openssl_EVP_sha1()
	case *sha224Hash:
		return C.go_openssl_EVP_sha224()
	case *sha256Hash:
		return C.go_openssl_EVP_sha256()
	case *sha384Hash:
		return C.go_openssl_EVP_sha384()
	case *sha512Hash:
		return C.go_openssl_EVP_sha512()
	}
	return nil
}

// cryptoHashToMD converts a crypto.Hash to a GO_EVP_MD_PTR.
func cryptoHashToMD(ch crypto.Hash) C.GO_EVP_MD_PTR {
	switch ch {
	case crypto.MD5:
		return C.go_openssl_EVP_md5()
	case crypto.MD5SHA1:
		if vMajor == 1 && vMinor == 0 {
			return C.go_openssl_EVP_md5_sha1_backport()
		} else {
			return C.go_openssl_EVP_md5_sha1()
		}
	case crypto.SHA1:
		return C.go_openssl_EVP_sha1()
	case crypto.SHA224:
		return C.go_openssl_EVP_sha224()
	case crypto.SHA256:
		return C.go_openssl_EVP_sha256()
	case crypto.SHA384:
		return C.go_openssl_EVP_sha384()
	case crypto.SHA512:
		return C.go_openssl_EVP_sha512()
	}
	return nil
}
