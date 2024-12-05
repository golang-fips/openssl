package ossl

const (
	KeyTypeRSA     = "RSA\x00"
	KeyTypeEC      = "EC\x00"
	KeyTypeED25519 = "ED25519\x00"
)

const (
	OSSL_KDF_NAME_HKDF     = "HKDF\x00"
	OSSL_KDF_NAME_PBKDF2   = "PBKDF2\x00"
	OSSL_KDF_NAME_TLS1_PRF = "TLS1-PRF\x00"
	OSSL_MAC_NAME_HMAC     = "HMAC\x00"
)

const POINT_CONVERSION_UNCOMPRESSED = 4

// #include <openssl/crypto.h>
const (
	OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002
	OPENSSL_INIT_ADD_ALL_CIPHERS     = 0x00000004
	OPENSSL_INIT_ADD_ALL_DIGESTS     = 0x00000008
	OPENSSL_INIT_LOAD_CONFIG         = 0x00000040
)

// #include <openssl/evp.h>
const (
	EVP_CTRL_GCM_GET_TAG = 0x10
	EVP_CTRL_GCM_SET_TAG = 0x11
	EVP_PKEY_CTRL_MD     = 1
	EVP_PKEY_RSA         = 6
	EVP_PKEY_EC          = 408
	EVP_PKEY_TLS1_PRF    = 1021
	EVP_PKEY_HKDF        = 1036
	EVP_PKEY_ED25519     = 1087
	EVP_PKEY_DSA         = 116
	/* This is defined differently in OpenSSL 3 (1 << 11), but in our
	 * code it is only used in OpenSSL 1.
	 */
	GO1_EVP_PKEY_OP_DERIVE = (1 << 10)
	EVP_MAX_MD_SIZE        = 64

	EVP_PKEY_PUBLIC_KEY = 0x86
	EVP_PKEY_KEYPAIR    = 0x87
)

// #include <openssl/ec.h>
const (
	EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = 0x1001
)

// #include <openssl/kdf.h>
const (
	EVP_KDF_HKDF_MODE_EXTRACT_ONLY = 1
	EVP_KDF_HKDF_MODE_EXPAND_ONLY  = 2

	EVP_PKEY_CTRL_TLS_MD     = 0x1000
	EVP_PKEY_CTRL_TLS_SECRET = 0x1001
	EVP_PKEY_CTRL_TLS_SEED   = 0x1002
	EVP_PKEY_CTRL_HKDF_MD    = 0x1003
	EVP_PKEY_CTRL_HKDF_SALT  = 0x1004
	EVP_PKEY_CTRL_HKDF_KEY   = 0x1005
	EVP_PKEY_CTRL_HKDF_INFO  = 0x1006
	EVP_PKEY_CTRL_HKDF_MODE  = 0x1007
)

// #include <openssl/obj_mac.h>
const (
	NID_X9_62_prime256v1 = 415
	NID_secp224r1        = 713
	NID_secp384r1        = 715
	NID_secp521r1        = 716
)

// #include <openssl/rsa.h>
const (
	RSA_PKCS1_PADDING                 = 1
	RSA_NO_PADDING                    = 3
	RSA_PKCS1_OAEP_PADDING            = 4
	RSA_PKCS1_PSS_PADDING             = 6
	RSA_PSS_SALTLEN_DIGEST            = -1
	RSA_PSS_SALTLEN_AUTO              = -2
	RSA_PSS_SALTLEN_MAX_SIGN          = -2
	RSA_PSS_SALTLEN_MAX               = -3
	EVP_PKEY_CTRL_RSA_PADDING         = 0x1001
	EVP_PKEY_CTRL_RSA_PSS_SALTLEN     = 0x1002
	EVP_PKEY_CTRL_RSA_KEYGEN_BITS     = 0x1003
	EVP_PKEY_CTRL_RSA_MGF1_MD         = 0x1005
	EVP_PKEY_CTRL_RSA_OAEP_MD         = 0x1009
	EVP_PKEY_CTRL_RSA_OAEP_LABEL      = 0x100A
	EVP_PKEY_CTRL_DSA_PARAMGEN_BITS   = 0x1001
	EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = 0x1002
)

const (
	// KDF parameters
	OSSL_KDF_PARAM_DIGEST = "digest\x00"
	OSSL_KDF_PARAM_SECRET = "secret\x00"
	OSSL_KDF_PARAM_SEED   = "seed\x00"
	OSSL_KDF_PARAM_KEY    = "key\x00"
	OSSL_KDF_PARAM_INFO   = "info\x00"
	OSSL_KDF_PARAM_SALT   = "salt\x00"
	OSSL_KDF_PARAM_MODE   = "mode\x00"

	// PKEY parameters
	OSSL_PKEY_PARAM_PUB_KEY          = "pub\x00"
	OSSL_PKEY_PARAM_PRIV_KEY         = "priv\x00"
	OSSL_PKEY_PARAM_GROUP_NAME       = "group\x00"
	OSSL_PKEY_PARAM_EC_PUB_X         = "qx\x00"
	OSSL_PKEY_PARAM_EC_PUB_Y         = "qy\x00"
	OSSL_PKEY_PARAM_FFC_PBITS        = "pbits\x00"
	OSSL_PKEY_PARAM_FFC_QBITS        = "qbits\x00"
	OSSL_PKEY_PARAM_RSA_N            = "n\x00"
	OSSL_PKEY_PARAM_RSA_E            = "e\x00"
	OSSL_PKEY_PARAM_RSA_D            = "d\x00"
	OSSL_PKEY_PARAM_FFC_P            = "p\x00"
	OSSL_PKEY_PARAM_FFC_Q            = "q\x00"
	OSSL_PKEY_PARAM_FFC_G            = "g\x00"
	OSSL_PKEY_PARAM_RSA_FACTOR1      = "rsa-factor1\x00"
	OSSL_PKEY_PARAM_RSA_FACTOR2      = "rsa-factor2\x00"
	OSSL_PKEY_PARAM_RSA_EXPONENT1    = "rsa-exponent1\x00"
	OSSL_PKEY_PARAM_RSA_EXPONENT2    = "rsa-exponent2\x00"
	OSSL_PKEY_PARAM_RSA_COEFFICIENT1 = "rsa-coefficient1\x00"

	// MAC parameters
	OSSL_MAC_PARAM_DIGEST = "digest\x00"
)
