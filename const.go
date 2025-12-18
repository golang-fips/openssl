package openssl

import "unsafe"

// cString is a null-terminated string,
// akin to C's char*.
type cString string

// str returns the string value.
func (s cString) str() string {
	return string(s)
}

// ptr returns a pointer to the string data.
// It panics if the string is not null-terminated.
//
// The memory pointed to by the returned pointer should
// not be modified and it must only be passed to
// "const char*" parameters. Any attempt to modify it
// will result in a runtime panic, as Go strings are
// allocated in read-only memory.
func (s cString) ptr() *byte {
	if len(s) == 0 {
		return nil
	}
	if s[len(s)-1] != 0 {
		panic("must be null-terminated")
	}
	return unsafe.StringData(string(s))
}

const ( //checkheader:ignore
	// Key types
	_KeyTypeRSA              cString = "RSA\x00"
	_KeyTypeEC               cString = "EC\x00"
	_KeyTypeED25519          cString = "ED25519\x00"
	_KeyTypeX25519           cString = "X25519\x00"
	_KeyTypeMLKEM768         cString = "ML-KEM-768\x00"
	_KeyTypeMLKEM1024        cString = "ML-KEM-1024\x00"
	_KeyTypeChacha20Poly1305 cString = "CHACHA20-POLY1305\x00"

	// Digest names
	_DigestNameSHAKE128 cString = "SHAKE-128\x00"
	_DigestNameSHAKE256 cString = "SHAKE-256\x00"

	// KDF names
	_OSSL_KDF_NAME_HKDF      cString = "HKDF\x00"
	_OSSL_KDF_NAME_PBKDF2    cString = "PBKDF2\x00"
	_OSSL_KDF_NAME_TLS1_PRF  cString = "TLS1-PRF\x00"
	_OSSL_KDF_NAME_TLS13_KDF cString = "TLS13-KDF\x00"
	_OSSL_MAC_NAME_HMAC      cString = "HMAC\x00"

	// KDF parameters
	_OSSL_KDF_PARAM_DIGEST cString = "digest\x00"
	_OSSL_KDF_PARAM_SECRET cString = "secret\x00"
	_OSSL_KDF_PARAM_SEED   cString = "seed\x00"
	_OSSL_KDF_PARAM_KEY    cString = "key\x00"
	_OSSL_KDF_PARAM_INFO   cString = "info\x00"
	_OSSL_KDF_PARAM_SALT   cString = "salt\x00"
	_OSSL_KDF_PARAM_MODE   cString = "mode\x00"

	// TLS3-KDF parameters
	_OSSL_KDF_PARAM_PREFIX cString = "prefix\x00"
	_OSSL_KDF_PARAM_LABEL  cString = "label\x00"
	_OSSL_KDF_PARAM_DATA   cString = "data\x00"

	// PKEY parameters
	_OSSL_PKEY_PARAM_PUB_KEY            cString = "pub\x00"
	_OSSL_PKEY_PARAM_PRIV_KEY           cString = "priv\x00"
	_OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY cString = "encoded-pub-key\x00"
	_OSSL_PKEY_PARAM_GROUP_NAME         cString = "group\x00"
	_OSSL_PKEY_PARAM_EC_PUB_X           cString = "qx\x00"
	_OSSL_PKEY_PARAM_EC_PUB_Y           cString = "qy\x00"
	_OSSL_PKEY_PARAM_FFC_PBITS          cString = "pbits\x00"
	_OSSL_PKEY_PARAM_FFC_QBITS          cString = "qbits\x00"
	_OSSL_PKEY_PARAM_RSA_N              cString = "n\x00"
	_OSSL_PKEY_PARAM_RSA_E              cString = "e\x00"
	_OSSL_PKEY_PARAM_RSA_D              cString = "d\x00"
	_OSSL_PKEY_PARAM_FFC_P              cString = "p\x00"
	_OSSL_PKEY_PARAM_FFC_Q              cString = "q\x00"
	_OSSL_PKEY_PARAM_FFC_G              cString = "g\x00"
	_OSSL_PKEY_PARAM_RSA_FACTOR1        cString = "rsa-factor1\x00"
	_OSSL_PKEY_PARAM_RSA_FACTOR2        cString = "rsa-factor2\x00"
	_OSSL_PKEY_PARAM_RSA_EXPONENT1      cString = "rsa-exponent1\x00"
	_OSSL_PKEY_PARAM_RSA_EXPONENT2      cString = "rsa-exponent2\x00"
	_OSSL_PKEY_PARAM_RSA_COEFFICIENT1   cString = "rsa-coefficient1\x00"
	_OSSL_PKEY_PARAM_ML_KEM_SEED        cString = "seed\x00"

	// MAC parameters
	_OSSL_MAC_PARAM_DIGEST cString = "digest\x00"
)
