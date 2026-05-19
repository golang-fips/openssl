//go:build !cmd_go_bootstrap

package openssl

import (
	"errors"
	"hash"
	"sync"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// SupportsPBKDF2 reports whether the current OpenSSL version supports PBKDF2.
func SupportsPBKDF2() bool {
	switch major() {
	case 1:
		return true
	case 3, 4:
		_, err := fetchPBKDF2()
		return err == nil
	default:
		panic(errUnsupportedVersion())
	}
}

// fetchPBKDF2 fetches the PBKDF2 algorithm.
// It is safe to call this function concurrently.
// The returned EVP_KDF_PTR shouldn't be freed.
var fetchPBKDF2 = sync.OnceValues(func() (ossl.EVP_KDF_PTR, error) {
	checkMajorVersion(3, 4)

	kdf, err := ossl.EVP_KDF_fetch(nil, _OSSL_KDF_NAME_PBKDF2.ptr(), nil)
	if err != nil {
		return nil, err
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
	switch major() {
	case 1:
		if _, err = ossl.PKCS5_PBKDF2_HMAC(password, salt, int32(iter), md, out); err != nil {
			return nil, err
		}
	default:
		kdf, err := fetchPBKDF2()
		if err != nil {
			return nil, err
		}
		ctx, err := ossl.EVP_KDF_CTX_new(kdf)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_KDF_CTX_free(ctx)

		bld := newParamBuilder()
		defer bld.finalize()
		bld.addOctetString(_OSSL_KDF_PARAM_PASSWORD, password)
		bld.addOctetString(_OSSL_KDF_PARAM_SALT, salt)
		bld.addInt32(_OSSL_KDF_PARAM_ITER, int32(iter))
		bld.addInt32(_OSSL_KDF_PARAM_PKCS5, 1) // disable SP800-132 compliance checks, they are done at the crypto/pbkdf2 level
		bld.addUTF8String(_OSSL_KDF_PARAM_DIGEST, ossl.EVP_MD_get0_name(md), 0)
		params, err := bld.build()
		if err != nil {
			return nil, err
		}
		defer ossl.OSSL_PARAM_free(params)

		_, err = ossl.EVP_KDF_derive(ctx, out, params)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}
