
#pragma GCC diagnostic ignored "-Wattributes"

#ifndef OSSL_H
#define OSSL_H

// Suppress warnings about unused parameters.
#define UNUSED(x) (void)(x)

// #include <openssl/evp.h>
enum {
    EVP_CTRL_GCM_GET_TAG = 0x10,
    EVP_CTRL_GCM_SET_TAG = 0x11,
};

typedef int point_conversion_form_t;

typedef void* OPENSSL_INIT_SETTINGS_PTR;
typedef void* OSSL_LIB_CTX_PTR;
typedef void* OSSL_PROVIDER_PTR;
typedef void* ENGINE_PTR;
typedef void* EVP_PKEY_PTR;
typedef void* EVP_PKEY_CTX_PTR;
typedef void* EVP_MD_PTR;
typedef void* EVP_MD_CTX_PTR;
typedef void* HMAC_CTX_PTR;
typedef void* EVP_CIPHER_PTR;
typedef void* EVP_CIPHER_CTX_PTR;
typedef void* EC_KEY_PTR;
typedef void* EC_POINT_PTR;
typedef void* EC_GROUP_PTR;
typedef void* RSA_PTR;
typedef void* BIGNUM_PTR;
typedef void* BN_CTX_PTR;
typedef void* EVP_MAC_PTR;
typedef void* EVP_MAC_CTX_PTR;
typedef void* OSSL_PARAM_BLD_PTR;
typedef void* OSSL_PARAM_PTR;
typedef void* CRYPTO_THREADID_PTR;
typedef void* EVP_SIGNATURE_PTR;
typedef void* DSA_PTR;
typedef void* EVP_KDF_PTR;
typedef void* EVP_KDF_CTX_PTR;
typedef void* MD5_CTX_PTR;
typedef void* SHA_CTX_PTR;

typedef void threadid_func(CRYPTO_THREADID_PTR);
typedef void locking_func(int mode, int n, const char *file, int line);

#endif // OSSL_H