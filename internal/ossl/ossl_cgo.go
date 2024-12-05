//go:build cgo

package ossl

/*
#include "ossl_extra.h"
#include <stdint.h>
#cgo linux LDFLAGS: -ldl -pthread
*/
import "C"
import "unsafe"

type Point_conversion_form_t = C.point_conversion_form_t

type OPENSSL_INIT_SETTINGS_PTR = C.OPENSSL_INIT_SETTINGS_PTR
type OSSL_LIB_CTX_PTR = C.OSSL_LIB_CTX_PTR
type OSSL_PROVIDER_PTR = C.OSSL_PROVIDER_PTR
type ENGINE_PTR = C.ENGINE_PTR
type EVP_PKEY_PTR = C.EVP_PKEY_PTR
type EVP_PKEY_CTX_PTR = C.EVP_PKEY_CTX_PTR
type EVP_MD_PTR = C.EVP_MD_PTR
type EVP_MD_CTX_PTR = C.EVP_MD_CTX_PTR
type HMAC_CTX_PTR = C.HMAC_CTX_PTR
type EVP_CIPHER_PTR = C.EVP_CIPHER_PTR
type EVP_CIPHER_CTX_PTR = C.EVP_CIPHER_CTX_PTR
type EC_KEY_PTR = C.EC_KEY_PTR
type EC_POINT_PTR = C.EC_POINT_PTR
type EC_GROUP_PTR = C.EC_GROUP_PTR
type RSA_PTR = C.RSA_PTR
type BIGNUM_PTR = C.BIGNUM_PTR
type BN_CTX_PTR = C.BN_CTX_PTR
type EVP_MAC_PTR = C.EVP_MAC_PTR
type EVP_MAC_CTX_PTR = C.EVP_MAC_CTX_PTR
type OSSL_PARAM_BLD_PTR = C.OSSL_PARAM_BLD_PTR
type OSSL_PARAM_PTR = C.OSSL_PARAM_PTR
type CRYPTO_THREADID_PTR = C.CRYPTO_THREADID_PTR
type EVP_SIGNATURE_PTR = C.EVP_SIGNATURE_PTR
type DSA_PTR = C.DSA_PTR
type EVP_KDF_PTR = C.EVP_KDF_PTR
type EVP_KDF_CTX_PTR = C.EVP_KDF_CTX_PTR
type MD5_CTX_PTR = C.MD5_CTX_PTR
type SHA_CTX_PTR = C.SHA_CTX_PTR

func EVP_EncryptUpdate_wrapper(ctx EVP_CIPHER_CTX_PTR, out *byte, in *byte, inl int32) (err error) {
	r0 := C.EVP_EncryptUpdate_wrapper(ctx, (*C.uint8_t)(unsafe.Pointer(out)), (*C.uint8_t)(unsafe.Pointer(in)), C.int32_t(inl))
	if r0 != 1 {
		err = newError("EVP_EncryptUpdate_wrapper")
	}
	return
}

func EVP_DecryptUpdate_wrapper(ctx EVP_CIPHER_CTX_PTR, out *byte, in *byte, inl int32) (err error) {
	r0 := C.EVP_DecryptUpdate_wrapper(ctx, (*C.uint8_t)(unsafe.Pointer(out)), (*C.uint8_t)(unsafe.Pointer(in)), C.int32_t(inl))
	if r0 != 1 {
		err = newError("EVP_DecryptUpdate_wrapper")
	}
	return
}

func EVP_CipherUpdate_wrapper(ctx EVP_CIPHER_CTX_PTR, out *byte, in *byte, inl int32) (err error) {
	r0 := C.EVP_CipherUpdate_wrapper(ctx, (*C.uint8_t)(unsafe.Pointer(out)), (*C.uint8_t)(unsafe.Pointer(in)), C.int32_t(inl))
	if r0 != 1 {
		err = newError("EVP_CipherUpdate_wrapper")
	}
	return
}

func EVP_CIPHER_CTX_seal_wrapper(ctx EVP_CIPHER_CTX_PTR, out *byte, nonce *byte, in *byte, inl int32, aad *byte, addl int32) (err error) {
	r0 := C.EVP_CIPHER_CTX_seal_wrapper(ctx,
		(*C.uint8_t)(unsafe.Pointer(out)),
		(*C.uint8_t)(unsafe.Pointer(nonce)),
		(*C.uint8_t)(unsafe.Pointer(in)),
		C.int32_t(inl),
		(*C.uint8_t)(unsafe.Pointer(aad)),
		C.int32_t(addl),
	)
	if r0 != 1 {
		err = newError("EVP_CIPHER_CTX_seal_wrapper")
	}
	return
}

func EVP_CIPHER_CTX_open_wrapper(ctx EVP_CIPHER_CTX_PTR, out *byte, nonce *byte, in *byte, inl int32, aad *byte, addl int32, tag *byte) (err error) {
	r0 := C.EVP_CIPHER_CTX_open_wrapper(ctx,
		(*C.uint8_t)(unsafe.Pointer(out)),
		(*C.uint8_t)(unsafe.Pointer(nonce)),
		(*C.uint8_t)(unsafe.Pointer(in)),
		C.int32_t(inl),
		(*C.uint8_t)(unsafe.Pointer(aad)),
		C.int32_t(addl),
		(*C.uint8_t)(unsafe.Pointer(tag)),
	)
	if r0 != 1 {
		err = newError("EVP_CIPHER_CTX_open_wrapper")
	}
	return
}

func DSA_get0_pqg_backport(dsa DSA_PTR, p, q, g *BIGNUM_PTR) {
	C.go_openssl_DSA_get0_pqg_backport(dsa, p, q, g)
}

func DSA_get0_key_backport(dsa DSA_PTR, pub_key, priv_key *BIGNUM_PTR) {
	C.go_openssl_DSA_get0_key_backport(dsa, pub_key, priv_key)
}

func DSA_set0_key_backport(dsa DSA_PTR, pub_key, priv_key BIGNUM_PTR) error {
	if C.go_openssl_DSA_set0_key_backport(dsa, pub_key, priv_key) != 1 {
		return newError("DSA_set0_key_backport")
	}
	return nil
}

func DSA_set0_pqg_backport(dsa DSA_PTR, p, q, g BIGNUM_PTR) error {
	if C.go_openssl_DSA_set0_pqg_backport(dsa, p, q, g) != 1 {
		return newError("DSA_set0_pqg_backport")
	}
	return nil
}

func EVP_md5_sha1_backport() EVP_MD_PTR {
	return C.go_openssl_EVP_md5_sha1_backport()
}

func HashSum(ctx, ctx2 EVP_MD_CTX_PTR, out *byte) error {
	if C.go_hash_sum(ctx, ctx2, (*C.uchar)(unsafe.Pointer(out))) != 1 {
		return newError("go_hash_sum")
	}
	return nil
}

func EVP_PKEY_derive_wrapper(ctx EVP_PKEY_CTX_PTR, key *byte, keylen int) (int, error) {
	r := C.EVP_PKEY_derive_wrapper(ctx, (*C.uchar)(unsafe.Pointer(key)), C.size_t(keylen))
	if r.result != 1 {
		return 0, newError("EVP_PKEY_derive_wrapper")
	}
	return int(r.keylen), nil
}

// Hand-roll custom wrappers for CRYPTO_malloc and CRYPTO_free which cast the
// function pointers to the correct signatures for OpenSSL 1.0.2.

func CRYPTO_malloc_legacy102(num int32, file *byte, line int32) unsafe.Pointer {
	return CRYPTO_malloc(int(num), file, line)
}

func CRYPTO_free_legacy102(str unsafe.Pointer) {
	CRYPTO_free(str, nil, 0)
}

func EVP_PKEY_get_raw_public_key_wrapper(pkey EVP_PKEY_PTR, out *byte, outlen int) (int, error) {
	r := C.EVP_PKEY_get_raw_public_key_wrapper(pkey, (*C.uchar)(unsafe.Pointer(out)), C.size_t(outlen))
	if r.result != 1 {
		return 0, newError("EVP_PKEY_get_raw_public_key")
	}
	return int(r.len), nil
}

func EVP_PKEY_get_raw_private_key_wrapper(pkey EVP_PKEY_PTR, out *byte, outlen int) (int, error) {
	r := C.EVP_PKEY_get_raw_private_key_wrapper(pkey, (*C.uchar)(unsafe.Pointer(out)), C.size_t(outlen))
	if r.result != 1 {
		return 0, newError("EVP_PKEY_get_raw_private_key")
	}
	return int(r.len), nil
}

func EVP_DigestSign_wrapper(ctx EVP_MD_CTX_PTR, sig *byte, siglen int, msg *byte, msglen int) (int, error) {
	r := C.EVP_DigestSign_wrapper(ctx, (*C.uchar)(unsafe.Pointer(sig)), C.size_t(siglen), (*C.uchar)(unsafe.Pointer(msg)), C.size_t(msglen))
	if r.result != 1 {
		return 0, newError("EVP_DigestSign")
	}
	return int(r.siglen), nil
}

func ThreadSetup() {
	if C.go_openssl_thread_setup() != 1 {
		panic("go_openssl_thread_setup")
	}
}

func Go_openssl_fips_enabled(handle unsafe.Pointer) int {
	return int(C.go_openssl_fips_enabled(handle))
}

func Go_openssl_version_major(handle unsafe.Pointer) int {
	return int(C.go_openssl_version_major(handle))
}

func Go_openssl_version_minor(handle unsafe.Pointer) int {
	return int(C.go_openssl_version_minor(handle))
}

func Go_openssl_version_patch(handle unsafe.Pointer) int {
	return int(C.go_openssl_version_patch(handle))
}
