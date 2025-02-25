package openssl

import "C"
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
func (s cString) ptr() *C.char {
	if len(s) == 0 {
		return nil
	}
	if s[len(s)-1] != 0 {
		panic("must be null-terminated")
	}
	return (*C.char)(unsafe.Pointer(unsafe.StringData(string(s))))
}

const ( //checkheader:ignore
	// Provider names
	_ProviderNameFips    cString = "fips\x00"
	_ProviderNameDefault cString = "default\x00"

	// Property strings
	_PropFIPSYes cString = "fips=yes\x00"
	_PropFIPSNo  cString = "-fips\x00"

	// Key types
	_KeyTypeRSA     cString = "RSA\x00"
	_KeyTypeEC      cString = "EC\x00"
	_KeyTypeED25519 cString = "ED25519\x00"

	// Digest Names
	_DigestNameSHA2_256 cString = "SHA2-256\x00"

	// KDF names
	_OSSL_KDF_NAME_HKDF     cString = "HKDF\x00"
	_OSSL_KDF_NAME_PBKDF2   cString = "PBKDF2\x00"
	_OSSL_KDF_NAME_TLS1_PRF cString = "TLS1-PRF\x00"
	_OSSL_MAC_NAME_HMAC     cString = "HMAC\x00"

	// KDF parameters
	_OSSL_KDF_PARAM_DIGEST cString = "digest\x00"
	_OSSL_KDF_PARAM_SECRET cString = "secret\x00"
	_OSSL_KDF_PARAM_SEED   cString = "seed\x00"
	_OSSL_KDF_PARAM_KEY    cString = "key\x00"
	_OSSL_KDF_PARAM_INFO   cString = "info\x00"
	_OSSL_KDF_PARAM_SALT   cString = "salt\x00"
	_OSSL_KDF_PARAM_MODE   cString = "mode\x00"

	// PKEY parameters
	_OSSL_PKEY_PARAM_PUB_KEY          cString = "pub\x00"
	_OSSL_PKEY_PARAM_PRIV_KEY         cString = "priv\x00"
	_OSSL_PKEY_PARAM_GROUP_NAME       cString = "group\x00"
	_OSSL_PKEY_PARAM_EC_PUB_X         cString = "qx\x00"
	_OSSL_PKEY_PARAM_EC_PUB_Y         cString = "qy\x00"
	_OSSL_PKEY_PARAM_FFC_PBITS        cString = "pbits\x00"
	_OSSL_PKEY_PARAM_FFC_QBITS        cString = "qbits\x00"
	_OSSL_PKEY_PARAM_RSA_N            cString = "n\x00"
	_OSSL_PKEY_PARAM_RSA_E            cString = "e\x00"
	_OSSL_PKEY_PARAM_RSA_D            cString = "d\x00"
	_OSSL_PKEY_PARAM_FFC_P            cString = "p\x00"
	_OSSL_PKEY_PARAM_FFC_Q            cString = "q\x00"
	_OSSL_PKEY_PARAM_FFC_G            cString = "g\x00"
	_OSSL_PKEY_PARAM_RSA_FACTOR1      cString = "rsa-factor1\x00"
	_OSSL_PKEY_PARAM_RSA_FACTOR2      cString = "rsa-factor2\x00"
	_OSSL_PKEY_PARAM_RSA_EXPONENT1    cString = "rsa-exponent1\x00"
	_OSSL_PKEY_PARAM_RSA_EXPONENT2    cString = "rsa-exponent2\x00"
	_OSSL_PKEY_PARAM_RSA_COEFFICIENT1 cString = "rsa-coefficient1\x00"

	// MAC parameters
	_OSSL_MAC_PARAM_DIGEST cString = "digest\x00"
)

// #include <openssl/crypto.h>
// #include <openssl/evp.h>
// #include <openssl/ec.h>
// #include <openssl/kdf.h>
// #include <openssl/obj_mac.h>
// #include <openssl/rsa.h>
// #if OPENSSL_VERSION_NUMBER >= 0x30000000L
// #include <openssl/core_names.h>
// #endif

const (
	_POINT_CONVERSION_UNCOMPRESSED = 4

	_OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002
	_OPENSSL_INIT_ADD_ALL_CIPHERS     = 0x00000004
	_OPENSSL_INIT_ADD_ALL_DIGESTS     = 0x00000008
	_OPENSSL_INIT_LOAD_CONFIG         = 0x00000040

	_EVP_CTRL_GCM_GET_TAG = 0x10
	_EVP_CTRL_GCM_SET_TAG = 0x11
	_EVP_PKEY_CTRL_MD     = 1
	_EVP_PKEY_RSA         = 6
	_EVP_PKEY_EC          = 408
	_EVP_PKEY_TLS1_PRF    = 1021
	_EVP_PKEY_HKDF        = 1036
	_EVP_PKEY_ED25519     = 1087
	_EVP_PKEY_DSA         = 116
	// This is defined differently in OpenSSL 3 (1 << 11),
	// but in our code it is only used in OpenSSL 1.
	_EVP_PKEY_OP_DERIVE = (1 << 10) //checkheader:ignore
	_EVP_MAX_MD_SIZE    = 64

	_EVP_PKEY_PUBLIC_KEY = 0x86
	_EVP_PKEY_KEYPAIR    = 0x87

	_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = 0x1001

	_EVP_KDF_HKDF_MODE_EXTRACT_ONLY = 1
	_EVP_KDF_HKDF_MODE_EXPAND_ONLY  = 2

	_EVP_PKEY_CTRL_TLS_MD     = 0x1000
	_EVP_PKEY_CTRL_TLS_SECRET = 0x1001
	_EVP_PKEY_CTRL_TLS_SEED   = 0x1002
	_EVP_PKEY_CTRL_HKDF_MD    = 0x1003
	_EVP_PKEY_CTRL_HKDF_SALT  = 0x1004
	_EVP_PKEY_CTRL_HKDF_KEY   = 0x1005
	_EVP_PKEY_CTRL_HKDF_INFO  = 0x1006
	_EVP_PKEY_CTRL_HKDF_MODE  = 0x1007

	_NID_X9_62_prime256v1 = 415
	_NID_secp224r1        = 713
	_NID_secp384r1        = 715
	_NID_secp521r1        = 716

	_RSA_PKCS1_PADDING                 = 1
	_RSA_NO_PADDING                    = 3
	_RSA_PKCS1_OAEP_PADDING            = 4
	_RSA_PKCS1_PSS_PADDING             = 6
	_RSA_PSS_SALTLEN_DIGEST            = -1
	_RSA_PSS_SALTLEN_AUTO              = -2
	_RSA_PSS_SALTLEN_MAX_SIGN          = -2
	_RSA_PSS_SALTLEN_MAX               = -3
	_EVP_PKEY_CTRL_RSA_PADDING         = 0x1001
	_EVP_PKEY_CTRL_RSA_PSS_SALTLEN     = 0x1002
	_EVP_PKEY_CTRL_RSA_KEYGEN_BITS     = 0x1003
	_EVP_PKEY_CTRL_RSA_MGF1_MD         = 0x1005
	_EVP_PKEY_CTRL_RSA_OAEP_MD         = 0x1009
	_EVP_PKEY_CTRL_RSA_OAEP_LABEL      = 0x100A
	_EVP_PKEY_CTRL_DSA_PARAMGEN_BITS   = 0x1001
	_EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = 0x1002
)
