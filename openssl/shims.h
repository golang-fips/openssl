#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t

// #include <openssl/crypto.h>
enum {
    GO_OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002L,
    GO_OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004L,
    GO_OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008L,
    GO_OPENSSL_INIT_LOAD_CONFIG = 0x00000040L
};

// #include <openssl/aes.h>
enum {
    GO_AES_ENCRYPT = 1,
    GO_AES_DECRYPT = 0
};

// #include <openssl/evp.h>
enum {
    GO_EVP_CTRL_GCM_GET_TAG = 0x10,
    GO_EVP_CTRL_GCM_SET_TAG = 0x11,
    GO_EVP_PKEY_CTRL_MD = 1,
    GO_EVP_PKEY_RSA = 6,
    GO_EVP_MAX_MD_SIZE = 64
};

// #include <openssl/rsa.h>
enum {
    GO_RSA_PKCS1_PADDING = 1,
    GO_RSA_NO_PADDING = 3,
    GO_RSA_PKCS1_OAEP_PADDING = 4,
    GO_RSA_PKCS1_PSS_PADDING = 6,
    GO_RSA_PSS_SALTLEN_DIGEST = -1,
    GO_RSA_PSS_SALTLEN_AUTO = -2,
    GO_RSA_PSS_SALTLEN_MAX_SIGN = -2,
    GO_RSA_PSS_SALTLEN_MAX = -3,
    GO_EVP_PKEY_CTRL_RSA_PADDING = 0x1001,
    GO_EVP_PKEY_CTRL_RSA_PSS_SALTLEN = 0x1002,
    GO_EVP_PKEY_CTRL_RSA_KEYGEN_BITS = 0x1003,
    GO_EVP_PKEY_CTRL_RSA_OAEP_MD = 0x1009,
    GO_EVP_PKEY_CTRL_RSA_OAEP_LABEL = 0x100A
};

typedef void* GO_OPENSSL_INIT_SETTINGS_PTR;
typedef void* GO_OSSL_LIB_CTX_PTR;
typedef void* GO_OSSL_PROVIDER_PTR;
typedef void* GO_ENGINE_PTR;
typedef void* GO_EVP_PKEY_PTR;
typedef void* GO_EVP_PKEY_CTX_PTR;
typedef void* GO_EVP_MD_PTR;
typedef void* GO_EVP_MD_CTX_PTR;
typedef void* GO_HMAC_CTX_PTR;
typedef void* GO_EVP_CIPHER_PTR;
typedef void* GO_EVP_CIPHER_CTX_PTR;
typedef void* GO_RSA_PTR;
typedef void* GO_BIGNUM_PTR;

// #include <openssl/md5.h>
typedef void* GO_MD5_CTX_PTR;

// #include <openssl/sha.h>
typedef void* GO_SHA_CTX_PTR;

// FOR_ALL_OPENSSL_FUNCTIONS is the list of all functions from libcrypto that are used in this package.
// Forgetting to add a function here results in build failure with message reporting the function
// that needs to be added.
//
// The purpose of FOR_ALL_OPENSSL_FUNCTIONS is to define all libcrypto functions
// without depending on the openssl headers so it is easier to use this package
// with an openssl version different that the one used at build time.
//
// The following macros may not be defined at this point,
// they are not resolved here but just accumulated in FOR_ALL_OPENSSL_FUNCTIONS.
//
// DEFINEFUNC defines and loads openssl functions that can be directly called from Go as their signatures match
// the OpenSSL API and do not require special logic.
// The process will be aborted if the function can't be loaded.
//
// DEFINEFUNC_LEGACY_1_0 acts like DEFINEFUNC but only aborts the process if the function can't be loaded
// when using 1.0.x. This indicates the function is required when using 1.0.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_LEGACY_1 acts like DEFINEFUNC but only aborts the process if the function can't be loaded
// when using 1.x. This indicates the function is required when using 1.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_1_1 acts like DEFINEFUNC but only aborts the process if function can't be loaded
// when using 1.1.0 or higher.
//
// DEFINEFUNC_3_0 acts like DEFINEFUNC but only aborts the process if function can't be loaded
// when using 3.0.0 or higher.
//
// DEFINEFUNC_RENAMED_1_1 acts like DEFINEFUNC but tries to load the function using the new name when using >= 1.1.x
// and the old name when using 1.0.2. In both cases the function will have the new name.
//
// DEFINEFUNC_RENAMED_3_0 acts like DEFINEFUNC but tries to load the function using the new name when using >= 3.x
// and the old name when using 1.x. In both cases the function will have the new name.
//
// #include <openssl/crypto.h>
// #include <openssl/err.h>
// #include <openssl/rsa.h>
// #include <openssl/hmac.h>
// #include <openssl/ec.h>
// #include <openssl/rand.h>
// #include <openssl/evp.h>
// #if OPENSSL_VERSION_NUMBER >= 0x30000000L
// #include <openssl/provider.h>
// #endif
#define FOR_ALL_OPENSSL_FUNCTIONS \
DEFINEFUNC(int, ERR_set_mark, (void), ()) \
DEFINEFUNC(int, ERR_pop_to_mark, (void), ()) \
DEFINEFUNC(void, ERR_error_string_n, (unsigned long e, char *buf, size_t len), (e, buf, len)) \
DEFINEFUNC_LEGACY_1(unsigned long, ERR_get_error_line, (const char **file, int *line), (file, line)) \
DEFINEFUNC_3_0(unsigned long, ERR_get_error_all, (const char **file, int *line, const char **func, const char **data, int *flags), (file, line, func, data, flags)) \
DEFINEFUNC_RENAMED_1_1(const char *, OpenSSL_version, SSLeay_version, (int type), (type)) \
DEFINEFUNC(void, OPENSSL_init, (void), ()) \
DEFINEFUNC_LEGACY_1_0(void, ERR_load_crypto_strings, (void), ()) \
DEFINEFUNC_LEGACY_1_0(int, CRYPTO_num_locks, (void), ()) \
DEFINEFUNC_LEGACY_1_0(void, CRYPTO_set_id_callback, (unsigned long (*id_function)(void)), (id_function)) \
DEFINEFUNC_LEGACY_1_0(void, CRYPTO_set_locking_callback, (void (*locking_function)(int mode, int n, const char *file, int line)), (locking_function)) \
DEFINEFUNC_LEGACY_1_0(void, OPENSSL_add_all_algorithms_conf, (void), ()) \
DEFINEFUNC_1_1(int, OPENSSL_init_crypto, (uint64_t ops, const GO_OPENSSL_INIT_SETTINGS_PTR settings), (ops, settings)) \
DEFINEFUNC_LEGACY_1(int, FIPS_mode, (void), ()) \
DEFINEFUNC_LEGACY_1(int, FIPS_mode_set, (int r), (r)) \
DEFINEFUNC_3_0(int, EVP_default_properties_is_fips_enabled, (GO_OSSL_LIB_CTX_PTR libctx), (libctx)) \
DEFINEFUNC_3_0(int, EVP_set_default_properties, (GO_OSSL_LIB_CTX_PTR libctx, const char *propq), (libctx, propq)) \
DEFINEFUNC_3_0(GO_OSSL_PROVIDER_PTR, OSSL_PROVIDER_load, (GO_OSSL_LIB_CTX_PTR libctx, const char *name), (libctx, name)) \
DEFINEFUNC_3_0(GO_EVP_MD_PTR, EVP_MD_fetch, (GO_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties), (ctx, algorithm, properties)) \
DEFINEFUNC_3_0(void, EVP_MD_free, (GO_EVP_MD_PTR md), (md)) \
DEFINEFUNC(int, RAND_bytes, (unsigned char* arg0, int arg1), (arg0, arg1)) \
DEFINEFUNC_RENAMED_1_1(GO_EVP_MD_CTX_PTR, EVP_MD_CTX_new, EVP_MD_CTX_create, (), ()) \
DEFINEFUNC_RENAMED_1_1(void, EVP_MD_CTX_free, EVP_MD_CTX_destroy, (GO_EVP_MD_CTX_PTR ctx), (ctx)) \
DEFINEFUNC(int, EVP_MD_CTX_copy, (GO_EVP_MD_CTX_PTR out, const GO_EVP_MD_CTX_PTR in), (out, in)) \
DEFINEFUNC(int, EVP_DigestInit_ex, (GO_EVP_MD_CTX_PTR ctx, const GO_EVP_MD_PTR type, GO_ENGINE_PTR impl), (ctx, type, impl)) \
DEFINEFUNC(int, EVP_DigestInit, (GO_EVP_MD_CTX_PTR ctx, const GO_EVP_MD_PTR type), (ctx, type)) \
DEFINEFUNC(int, EVP_DigestUpdate, (GO_EVP_MD_CTX_PTR ctx, const void *d, size_t cnt), (ctx, d, cnt)) \
DEFINEFUNC(int, EVP_DigestFinal_ex, (GO_EVP_MD_CTX_PTR ctx, unsigned char *md, unsigned int *s), (ctx, md, s)) \
DEFINEFUNC(int, EVP_DigestFinal, (GO_EVP_MD_CTX_PTR ctx, unsigned char *md, unsigned int *s), (ctx, md, s)) \
DEFINEFUNC(int, EVP_DigestSignInit, (GO_EVP_MD_CTX_PTR ctx, GO_EVP_PKEY_CTX_PTR *pctx, const GO_EVP_MD_PTR type, GO_ENGINE_PTR e, GO_EVP_PKEY_PTR pkey), (ctx, pctx, type, e, pkey)) \
DEFINEFUNC(int, EVP_DigestSignFinal, (GO_EVP_MD_CTX_PTR ctx, unsigned char *sig, size_t *siglen), (ctx, sig, siglen)) \
DEFINEFUNC(int, EVP_DigestVerifyInit, (GO_EVP_MD_CTX_PTR ctx, GO_EVP_PKEY_CTX_PTR *pctx, const GO_EVP_MD_PTR type, GO_ENGINE_PTR e, GO_EVP_PKEY_PTR pkey), (ctx, pctx, type, e, pkey)) \
DEFINEFUNC(int, EVP_DigestVerifyFinal, (GO_EVP_MD_CTX_PTR ctx, const unsigned char *sig, size_t siglen), (ctx, sig, siglen)) \
DEFINEFUNC_LEGACY_1_0(int, MD5_Init, (GO_MD5_CTX_PTR c), (c)) \
DEFINEFUNC_LEGACY_1_0(int, MD5_Update, (GO_MD5_CTX_PTR c, const void *data, size_t len), (c, data, len)) \
DEFINEFUNC_LEGACY_1_0(int, MD5_Final, (unsigned char *md, GO_MD5_CTX_PTR c), (md, c)) \
DEFINEFUNC_LEGACY_1_0(int, SHA1_Init, (GO_SHA_CTX_PTR c), (c)) \
DEFINEFUNC_LEGACY_1_0(int, SHA1_Update, (GO_SHA_CTX_PTR c, const void *data, size_t len), (c, data, len)) \
DEFINEFUNC_LEGACY_1_0(int, SHA1_Final, (unsigned char *md, GO_SHA_CTX_PTR c), (md, c)) \
DEFINEFUNC_1_1(const GO_EVP_MD_PTR, EVP_md5_sha1, (void), ()) \
DEFINEFUNC(const GO_EVP_MD_PTR, EVP_md5, (void), ()) \
DEFINEFUNC(const GO_EVP_MD_PTR, EVP_sha1, (void), ()) \
DEFINEFUNC(const GO_EVP_MD_PTR, EVP_sha224, (void), ()) \
DEFINEFUNC(const GO_EVP_MD_PTR, EVP_sha256, (void), ()) \
DEFINEFUNC(const GO_EVP_MD_PTR, EVP_sha384, (void), ()) \
DEFINEFUNC(const GO_EVP_MD_PTR, EVP_sha512, (void), ()) \
DEFINEFUNC_RENAMED_3_0(int, EVP_MD_get_size, EVP_MD_size, (const GO_EVP_MD_PTR arg0), (arg0)) \
DEFINEFUNC_LEGACY_1_0(void, HMAC_CTX_init, (GO_HMAC_CTX_PTR arg0), (arg0)) \
DEFINEFUNC_LEGACY_1_0(void, HMAC_CTX_cleanup, (GO_HMAC_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(int, HMAC_Init_ex, (GO_HMAC_CTX_PTR arg0, const void *arg1, int arg2, const GO_EVP_MD_PTR arg3, GO_ENGINE_PTR arg4), (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, HMAC_Update, (GO_HMAC_CTX_PTR arg0, const unsigned char *arg1, size_t arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, HMAC_Final, (GO_HMAC_CTX_PTR arg0, unsigned char *arg1, unsigned int *arg2), (arg0, arg1, arg2)) \
DEFINEFUNC(int, HMAC_CTX_copy, (GO_HMAC_CTX_PTR dest, GO_HMAC_CTX_PTR src), (dest, src)) \
DEFINEFUNC_1_1(void, HMAC_CTX_free, (GO_HMAC_CTX_PTR arg0), (arg0)) \
DEFINEFUNC_1_1(GO_HMAC_CTX_PTR, HMAC_CTX_new, (void), ()) \
DEFINEFUNC_1_1(int, HMAC_CTX_reset, (GO_HMAC_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(GO_EVP_CIPHER_CTX_PTR, EVP_CIPHER_CTX_new, (void), ()) \
DEFINEFUNC(int, EVP_CIPHER_CTX_set_padding, (GO_EVP_CIPHER_CTX_PTR x, int padding), (x, padding)) \
DEFINEFUNC(int, EVP_CipherInit_ex, (GO_EVP_CIPHER_CTX_PTR ctx, const GO_EVP_CIPHER_PTR type, GO_ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv, int enc), (ctx, type, impl, key, iv, enc)) \
DEFINEFUNC(int, EVP_CipherUpdate, (GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl), (ctx, out, outl, in, inl)) \
DEFINEFUNC(int, EVP_EncryptInit_ex, (GO_EVP_CIPHER_CTX_PTR ctx, const GO_EVP_CIPHER_PTR type, GO_ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv), (ctx, type, impl, key, iv)) \
DEFINEFUNC(int, EVP_EncryptUpdate, (GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl), (ctx, out, outl, in, inl)) \
DEFINEFUNC(int, EVP_EncryptFinal_ex, (GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl), (ctx, out, outl)) \
DEFINEFUNC(int, EVP_DecryptUpdate, (GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl),	(ctx, out, outl, in, inl)) \
DEFINEFUNC(int, EVP_DecryptFinal_ex, (GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *outm, int *outl),	(ctx, outm, outl)) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_128_gcm, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_128_cbc, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_128_ctr, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_128_ecb, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_192_gcm, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_192_cbc, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_192_ctr, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_192_ecb, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_256_cbc, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_256_ctr, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_256_ecb, (void), ()) \
DEFINEFUNC(const GO_EVP_CIPHER_PTR, EVP_aes_256_gcm, (void), ()) \
DEFINEFUNC(void, EVP_CIPHER_CTX_free, (GO_EVP_CIPHER_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(int, EVP_CIPHER_CTX_ctrl, (GO_EVP_CIPHER_CTX_PTR ctx, int type, int arg, void *ptr), (ctx, type, arg, ptr)) \
DEFINEFUNC(GO_EVP_PKEY_PTR, EVP_PKEY_new, (void), ()) \
/* EVP_PKEY_size pkey parameter is const since OpenSSL 1.1.1. */ \
/* Exclude it from headercheck tool when using previous OpenSSL versions. */ \
/*check:from=1.1.1*/ DEFINEFUNC_RENAMED_3_0(int, EVP_PKEY_get_size, EVP_PKEY_size, (const GO_EVP_PKEY_PTR pkey), (pkey)) \
DEFINEFUNC(void, EVP_PKEY_free, (GO_EVP_PKEY_PTR arg0), (arg0)) \
DEFINEFUNC(GO_RSA_PTR, EVP_PKEY_get1_RSA, (GO_EVP_PKEY_PTR pkey), (pkey)) \
DEFINEFUNC(int, EVP_PKEY_assign, (GO_EVP_PKEY_PTR pkey, int type, void *key), (pkey, type, key)) \
DEFINEFUNC(int, EVP_PKEY_verify, (GO_EVP_PKEY_CTX_PTR ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen), (ctx, sig, siglen, tbs, tbslen)) \
DEFINEFUNC(GO_EVP_PKEY_CTX_PTR, EVP_PKEY_CTX_new, (GO_EVP_PKEY_PTR arg0, GO_ENGINE_PTR arg1), (arg0, arg1)) \
DEFINEFUNC(GO_EVP_PKEY_CTX_PTR, EVP_PKEY_CTX_new_id, (int id, GO_ENGINE_PTR e), (id, e)) \
DEFINEFUNC(int, EVP_PKEY_keygen_init, (GO_EVP_PKEY_CTX_PTR ctx), (ctx)) \
DEFINEFUNC(int, EVP_PKEY_keygen, (GO_EVP_PKEY_CTX_PTR ctx, GO_EVP_PKEY_PTR *ppkey), (ctx, ppkey)) \
DEFINEFUNC(void, EVP_PKEY_CTX_free, (GO_EVP_PKEY_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_CTX_ctrl, (GO_EVP_PKEY_CTX_PTR ctx, int keytype, int optype, int cmd, int p1, void *p2), (ctx, keytype, optype, cmd, p1, p2)) \
DEFINEFUNC(int, EVP_PKEY_decrypt, (GO_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4), (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, EVP_PKEY_encrypt, (GO_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4), (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(int, EVP_PKEY_decrypt_init, (GO_EVP_PKEY_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_encrypt_init, (GO_EVP_PKEY_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_sign_init, (GO_EVP_PKEY_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_verify_init, (GO_EVP_PKEY_CTX_PTR arg0), (arg0)) \
DEFINEFUNC(int, EVP_PKEY_sign, (GO_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4), (arg0, arg1, arg2, arg3, arg4)) \
DEFINEFUNC(GO_RSA_PTR, RSA_new, (void), ()) \
DEFINEFUNC(void, RSA_free, (GO_RSA_PTR arg0), (arg0)) \
DEFINEFUNC_1_1(int, RSA_set0_factors, (GO_RSA_PTR rsa, GO_BIGNUM_PTR p, GO_BIGNUM_PTR q), (rsa, p, q)) \
DEFINEFUNC_1_1(int, RSA_set0_crt_params, (GO_RSA_PTR rsa, GO_BIGNUM_PTR dmp1, GO_BIGNUM_PTR dmp2,GO_BIGNUM_PTR iqmp), (rsa, dmp1, dmp2, iqmp)) \
DEFINEFUNC_1_1(void, RSA_get0_crt_params, (const GO_RSA_PTR r, const GO_BIGNUM_PTR *dmp1, const GO_BIGNUM_PTR *dmq1, const GO_BIGNUM_PTR *iqmp), (r, dmp1, dmq1, iqmp)) \
DEFINEFUNC_1_1(int, RSA_set0_key, (GO_RSA_PTR r, GO_BIGNUM_PTR n, GO_BIGNUM_PTR e, GO_BIGNUM_PTR d), (r, n, e, d)) \
DEFINEFUNC_1_1(void, RSA_get0_factors, (const GO_RSA_PTR rsa, const GO_BIGNUM_PTR *p, const GO_BIGNUM_PTR *q), (rsa, p, q)) \
DEFINEFUNC_1_1(void, RSA_get0_key, (const GO_RSA_PTR rsa, const GO_BIGNUM_PTR *n, const GO_BIGNUM_PTR *e, const GO_BIGNUM_PTR *d), (rsa, n, e, d)) \
DEFINEFUNC(void, BN_clear_free, (GO_BIGNUM_PTR arg0), (arg0)) \
DEFINEFUNC(int, BN_num_bits, (const GO_BIGNUM_PTR arg0), (arg0)) \
/* bn_lebin2bn and bn_bn2lebinpad are not exported in any OpenSSL 1.0.2, but they exist. */ \
/*check:from=1.1.0*/ DEFINEFUNC_RENAMED_1_1(GO_BIGNUM_PTR, BN_lebin2bn, bn_lebin2bn, (const unsigned char *s, int len, GO_BIGNUM_PTR ret), (s, len, ret)) \
/*check:from=1.1.0*/ DEFINEFUNC_RENAMED_1_1(int, BN_bn2lebinpad, bn_bn2lebinpad, (const GO_BIGNUM_PTR a, unsigned char *to, int tolen), (a, to, tolen))
