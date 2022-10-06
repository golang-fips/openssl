package openssl

// #include "goopenssl.h"
import "C"
import "crypto"

// cryptoHashToMD converts a crypto.Hash to a GO_EVP_MD_PTR.
func cryptoHashToMD(ch crypto.Hash) C.GO_EVP_MD_PTR {
	switch ch {
	case crypto.MD5:
		// TODO: not necessary yet
	case crypto.MD5SHA1:
		// TODO: not necessary yet
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
