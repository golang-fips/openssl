#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t

typedef void* _OPENSSL_INIT_SETTINGS_PTR;
typedef void* _OSSL_LIB_CTX_PTR;
typedef void* _OSSL_PROVIDER_PTR;
typedef void* _ENGINE_PTR;
typedef void* _EVP_PKEY_PTR;
typedef void* _EVP_PKEY_CTX_PTR;
typedef void* _EVP_MD_PTR;
typedef void* _EVP_MD_CTX_PTR;
typedef void* _HMAC_CTX_PTR;
typedef void* _EVP_CIPHER_PTR;
typedef void* _EVP_CIPHER_CTX_PTR;
typedef void* _EC_KEY_PTR;
typedef void* _EC_POINT_PTR;
typedef void* _EC_GROUP_PTR;
typedef void* _RSA_PTR;
typedef void* _BIGNUM_PTR;
typedef void* _BN_CTX_PTR;
typedef void* _EVP_MAC_PTR;
typedef void* _EVP_MAC_CTX_PTR;
typedef void* _OSSL_PARAM_BLD_PTR;
typedef void* _OSSL_PARAM_PTR;
typedef void* go_CRYPTO_THREADID_PTR;
typedef void* _EVP_SIGNATURE_PTR;
typedef void* _DSA_PTR;
typedef void* _EVP_KDF_PTR;
typedef void* _EVP_KDF_CTX_PTR;
typedef void* go_MD5_CTX_PTR;
typedef void* go_SHA_CTX_PTR;
typedef int point_conversion_form_t;

// Tags used to determine which OpenSSL version the function is available in:
// no tag: OpenSSL 1.0 or later
// legacy_1: Only OpenSSL 1
// 3: OpenSSL 3.0 or later
// 111: OpenSSL 1.1.1 or later

// #include <openssl/crypto.h>
// #include <openssl/err.h>
// #include <openssl/rsa.h>
// #include <openssl/hmac.h>
// #include <openssl/ec.h>
// #include <openssl/rand.h>
// #include <openssl/evp.h>
// #include <openssl/dsa.h>
// #include <openssl/kdf.h>
// #if OPENSSL_VERSION_NUMBER >= 0x30000000L
// #include <openssl/provider.h>
// #include <openssl/param_build.h>
// #endif
// #if OPENSSL_VERSION_NUMBER < 0x10100000L
// #include <openssl/bn.h>
// #endif
/*[[mkcgo]]*/ void ERR_error_string_n(unsigned long e, char *buf, size_t len);
/*[[mkcgo]]*/ void ERR_clear_error(void);
/*[[mkcgo::tag("legacy_1")]]*/ unsigned long ERR_get_error_line(const char **file, int *line);
/*[[mkcgo::tag("3")]]*/ unsigned long ERR_get_error_all(const char **file, int *line, const char **func, const char **data, int *flags);
/*[[mkcgo]]*/ const char *OpenSSL_version(int type);
/*[[mkcgo]]*/ void OPENSSL_init(void);
/* CRYPTO_malloc argument num changes from int to size_t in OpenSSL 1.1.0, */
/* and CRYPTO_free has file and line arguments added. */
/* Exclude them from headercheck tool when using previous OpenSSL versions. */
/*[[mkcgo]]*/ void *CRYPTO_malloc(size_t num, const char *file, int line);
/*[[mkcgo]]*/ void CRYPTO_free(void *str, const char *file, int line);
/*[[mkcgo]]*/ int OPENSSL_init_crypto(uint64_t ops, const _OPENSSL_INIT_SETTINGS_PTR settings);
/*[[mkcgo::tag("legacy_1")]]*/ int FIPS_mode(void);
/*[[mkcgo::tag("legacy_1")]]*/ int FIPS_mode_set(int r);
/*[[mkcgo::tag("3")]]*/ int EVP_default_properties_is_fips_enabled(_OSSL_LIB_CTX_PTR libctx);
/*[[mkcgo::tag("3")]]*/ int EVP_default_properties_enable_fips(_OSSL_LIB_CTX_PTR libctx, int enable);
/*[[mkcgo::tag("3")]]*/ int OSSL_PROVIDER_available(_OSSL_LIB_CTX_PTR libctx, const char *name);
/*[[mkcgo::tag("3")]]*/ _OSSL_PROVIDER_PTR OSSL_PROVIDER_try_load(_OSSL_LIB_CTX_PTR libctx, const char *name, int retain_fallbacks);
/*[[mkcgo::tag("3")]]*/ const char *OSSL_PROVIDER_get0_name(const _OSSL_PROVIDER_PTR prov);
/*[[mkcgo::tag("3")]]*/ _EVP_MD_PTR EVP_MD_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);
/*[[mkcgo::tag("3")]]*/ void EVP_MD_free(_EVP_MD_PTR md);
/*[[mkcgo::tag("3")]]*/ const char *EVP_MD_get0_name(const _EVP_MD_PTR md);
/*[[mkcgo::tag("3")]]*/ int EVP_MD_get_type(const _EVP_MD_PTR md);
/*[[mkcgo::tag("3")]]*/ const _OSSL_PROVIDER_PTR EVP_MD_get0_provider(const _EVP_MD_PTR md);
/*[[mkcgo::tag("legacy_1")]]*/ int EVP_MD_size(const _EVP_MD_PTR md);
/*[[mkcgo::tag("3")]]*/ int EVP_MD_get_size(const _EVP_MD_PTR md);
/*[[mkcgo::tag("legacy_1")]]*/ int EVP_MD_block_size(const _EVP_MD_PTR md);
/*[[mkcgo::tag("3")]]*/ int EVP_MD_get_block_size(const _EVP_MD_PTR md);
/*[[mkcgo]]*/ int RAND_bytes(unsigned char *arg0, int arg1);
/*[[mkcgo]]*/ _EVP_MD_CTX_PTR EVP_MD_CTX_new(void);
/*[[mkcgo]]*/ void EVP_MD_CTX_free(_EVP_MD_CTX_PTR ctx);
/*[[mkcgo]]*/ int EVP_MD_CTX_copy(_EVP_MD_CTX_PTR out, const _EVP_MD_CTX_PTR in);
/*[[mkcgo]]*/ int EVP_MD_CTX_copy_ex(_EVP_MD_CTX_PTR out, const _EVP_MD_CTX_PTR in);
/*[[mkcgo]]*/ int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const _EVP_MD_PTR type, _ENGINE_PTR impl);
/*[[mkcgo]]*/ int EVP_DigestInit_ex(_EVP_MD_CTX_PTR ctx, const _EVP_MD_PTR type, _ENGINE_PTR impl);
/*[[mkcgo]]*/ int EVP_DigestInit(_EVP_MD_CTX_PTR ctx, const _EVP_MD_PTR type);
/*[[mkcgo]]*/ int EVP_DigestUpdate(_EVP_MD_CTX_PTR ctx, const void *d, size_t cnt);
/*[[mkcgo]]*/ int EVP_DigestFinal_ex(_EVP_MD_CTX_PTR ctx, unsigned char *md, unsigned int *s);
/*[[mkcgo::tag("111")]]*/ int EVP_DigestSign(_EVP_MD_CTX_PTR ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
/*[[mkcgo]]*/ int EVP_DigestSignInit(_EVP_MD_CTX_PTR ctx, _EVP_PKEY_CTX_PTR *pctx, const _EVP_MD_PTR type, _ENGINE_PTR e, _EVP_PKEY_PTR pkey);
/*[[mkcgo]]*/ int EVP_DigestSignFinal(_EVP_MD_CTX_PTR ctx, unsigned char *sig, size_t *siglen);
/*[[mkcgo]]*/ int EVP_DigestVerifyInit(_EVP_MD_CTX_PTR ctx, _EVP_PKEY_CTX_PTR *pctx, const _EVP_MD_PTR type, _ENGINE_PTR e, _EVP_PKEY_PTR pkey);
/*[[mkcgo]]*/ int EVP_DigestVerifyFinal(_EVP_MD_CTX_PTR ctx, const unsigned char *sig, size_t siglen);
/*[[mkcgo::tag("111")]]*/ int EVP_DigestVerify(_EVP_MD_CTX_PTR ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_md5_sha1(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_ripemd160(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_md4(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_md5(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_sha1(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_sha224(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_sha256(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_sha384(void);
/*[[mkcgo]]*/ const _EVP_MD_PTR EVP_sha512(void);
/*[[mkcgo::tag("111")]]*/ const _EVP_MD_PTR EVP_sha512_224(void);
/*[[mkcgo::tag("111")]]*/ const _EVP_MD_PTR EVP_sha512_256(void);
/*[[mkcgo::tag("111")]]*/ const _EVP_MD_PTR EVP_sha3_224(void);
/*[[mkcgo::tag("111")]]*/ const _EVP_MD_PTR EVP_sha3_256(void);
/*[[mkcgo::tag("111")]]*/ const _EVP_MD_PTR EVP_sha3_384(void);
/*[[mkcgo::tag("111")]]*/ const _EVP_MD_PTR EVP_sha3_512(void);
/*[[mkcgo::tag("legacy_1")]]*/ int HMAC_Init_ex(_HMAC_CTX_PTR arg0, const void *arg1, int arg2, const _EVP_MD_PTR arg3, _ENGINE_PTR arg4);
/*[[mkcgo::tag("legacy_1")]]*/ int HMAC_Update(_HMAC_CTX_PTR arg0, const unsigned char *arg1, size_t arg2);
/*[[mkcgo::tag("legacy_1")]]*/ int HMAC_Final(_HMAC_CTX_PTR arg0, unsigned char *arg1, unsigned int *arg2);
/*[[mkcgo::tag("legacy_1")]]*/ int HMAC_CTX_copy(_HMAC_CTX_PTR dest, _HMAC_CTX_PTR src);
/*[[mkcgo::tag("legacy_1")]]*/ void HMAC_CTX_free(_HMAC_CTX_PTR arg0);
/*[[mkcgo::tag("legacy_1")]]*/ _HMAC_CTX_PTR HMAC_CTX_new(void);
/*[[mkcgo]]*/ _EVP_CIPHER_CTX_PTR EVP_CIPHER_CTX_new(void);
/*[[mkcgo]]*/ int EVP_CIPHER_CTX_set_padding(_EVP_CIPHER_CTX_PTR x, int padding);
/*[[mkcgo]]*/ int EVP_CipherInit_ex(_EVP_CIPHER_CTX_PTR ctx, const _EVP_CIPHER_PTR type, _ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv, int enc);
/*[[mkcgo]]*/ int EVP_CipherUpdate(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
/*[[mkcgo]]*/ int EVP_EncryptInit_ex(_EVP_CIPHER_CTX_PTR ctx, const _EVP_CIPHER_PTR type, _ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv);
/*[[mkcgo]]*/ int EVP_EncryptUpdate(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
/*[[mkcgo]]*/ int EVP_EncryptFinal_ex(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl);
/*[[mkcgo]]*/ int EVP_DecryptInit_ex(_EVP_CIPHER_CTX_PTR ctx, const _EVP_CIPHER_PTR type, _ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv);
/*[[mkcgo]]*/ int EVP_DecryptUpdate(_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
/*[[mkcgo]]*/ int EVP_DecryptFinal_ex(_EVP_CIPHER_CTX_PTR ctx, unsigned char *outm, int *outl);
/*[[mkcgo::tag("3")]]*/ _EVP_CIPHER_PTR EVP_CIPHER_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);
/*[[mkcgo::tag("3")]]*/ const char *EVP_CIPHER_get0_name(const _EVP_CIPHER_PTR cipher);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_128_gcm(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_128_cbc(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_128_ctr(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_128_ecb(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_192_gcm(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_192_cbc(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_192_ctr(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_192_ecb(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_256_cbc(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_256_ctr(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_256_ecb(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_aes_256_gcm(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_des_ecb(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_des_cbc(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_des_ede3_ecb(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_des_ede3_cbc(void);
/*[[mkcgo]]*/ const _EVP_CIPHER_PTR EVP_rc4(void);
/*[[mkcgo::tag("legacy_1")]]*/ int EVP_CIPHER_block_size(const _EVP_CIPHER_PTR cipher);
/*[[mkcgo::tag("3")]]*/ int EVP_CIPHER_get_block_size(const _EVP_CIPHER_PTR cipher);
/*[[mkcgo]]*/ int EVP_CIPHER_CTX_set_key_length(_EVP_CIPHER_CTX_PTR x, int keylen);
/*[[mkcgo]]*/ void EVP_CIPHER_CTX_free(_EVP_CIPHER_CTX_PTR arg0);
/*[[mkcgo]]*/ int EVP_CIPHER_CTX_ctrl(_EVP_CIPHER_CTX_PTR ctx, int type, int arg, void *ptr);
/*[[mkcgo]]*/ _EVP_PKEY_PTR EVP_PKEY_new(void);
/*[[mkcgo::tag("111")]]*/ _EVP_PKEY_PTR EVP_PKEY_new_raw_private_key(int type, _ENGINE_PTR e, const unsigned char *key, size_t keylen);
/*[[mkcgo::tag("111")]]*/ _EVP_PKEY_PTR EVP_PKEY_new_raw_public_key(int type, _ENGINE_PTR e, const unsigned char *key, size_t keylen);
/*[[mkcgo::tag("legacy_1")]]*/ int EVP_PKEY_size(const _EVP_PKEY_PTR pkey);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_get_size(const _EVP_PKEY_PTR pkey);
/*[[mkcgo::tag("legacy_1")]]*/ int EVP_PKEY_bits(const _EVP_PKEY_PTR pkey);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_get_bits(const _EVP_PKEY_PTR pkey); 
/*[[mkcgo]]*/ void EVP_PKEY_free(_EVP_PKEY_PTR arg0);
/*[[mkcgo::tag("legacy_1")]]*/ _RSA_PTR EVP_PKEY_get1_RSA(_EVP_PKEY_PTR pkey);
/*[[mkcgo::tag("legacy_1")]]*/ int EVP_PKEY_assign(_EVP_PKEY_PTR pkey, int type, void *key);
/*[[mkcgo]]*/ int EVP_PKEY_verify(_EVP_PKEY_CTX_PTR ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
/*[[mkcgo]]*/ _EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new(_EVP_PKEY_PTR arg0, _ENGINE_PTR arg1);
/*[[mkcgo]]*/ _EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new_id(int id, _ENGINE_PTR e);
/*[[mkcgo::tag("3")]]*/ _EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new_from_pkey(_OSSL_LIB_CTX_PTR libctx, _EVP_PKEY_PTR pkey, const char *propquery);
/*[[mkcgo]]*/ int EVP_PKEY_paramgen_init(_EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo]]*/ int EVP_PKEY_paramgen(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR *ppkey);
/*[[mkcgo]]*/ int EVP_PKEY_keygen_init(_EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo]]*/ int EVP_PKEY_keygen(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR *ppkey);
/*[[mkcgo::tag("3")]]*/ _EVP_PKEY_PTR EVP_PKEY_Q_keygen(_OSSL_LIB_CTX_PTR ctx, const char *propq, const char *type);
/*[[mkcgo::tag("3")]] [[mkcgo::variadic("EVP_PKEY_Q_keygen")]]*/ _EVP_PKEY_PTR EVP_PKEY_Q_keygen_RSA(_OSSL_LIB_CTX_PTR ctx, const char *propq, const char *type, size_t arg1);
/*[[mkcgo::tag("3")]] [[mkcgo::variadic("EVP_PKEY_Q_keygen")]]*/ _EVP_PKEY_PTR EVP_PKEY_Q_keygen_EC(_OSSL_LIB_CTX_PTR ctx, const char *propq, const char *type, const char *arg1);
/*[[mkcgo]]*/ void EVP_PKEY_CTX_free(_EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo]]*/ int EVP_PKEY_CTX_ctrl(_EVP_PKEY_CTX_PTR ctx, int keytype, int optype, int cmd, int p1, void *p2);
/*[[mkcgo]]*/ int EVP_PKEY_decrypt(_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
/*[[mkcgo]]*/ int EVP_PKEY_encrypt(_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
/*[[mkcgo]]*/ int EVP_PKEY_decrypt_init(_EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo]]*/ int EVP_PKEY_encrypt_init(_EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo]]*/ int EVP_PKEY_sign_init(_EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo]]*/ int EVP_PKEY_verify_init(_EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo]]*/ int EVP_PKEY_sign(_EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
/*[[mkcgo]]*/ int EVP_PKEY_derive_init(_EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo]]*/ int EVP_PKEY_derive_set_peer(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR peer);
/*[[mkcgo]]*/ int EVP_PKEY_derive(_EVP_PKEY_CTX_PTR ctx, unsigned char *key, size_t *keylen);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_public_check_quick(_EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_private_check(_EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo::tag("legacy_1")]]*/ _EC_KEY_PTR EVP_PKEY_get0_EC_KEY(_EVP_PKEY_PTR pkey);
/*[[mkcgo::tag("legacy_1")]]*/ _DSA_PTR EVP_PKEY_get0_DSA(_EVP_PKEY_PTR pkey);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_fromdata_init(_EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_fromdata(_EVP_PKEY_CTX_PTR ctx, _EVP_PKEY_PTR *pkey, int selection, _OSSL_PARAM_PTR params);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_set1_encoded_public_key(_EVP_PKEY_PTR pkey, const unsigned char *pub, size_t publen);
/*[[mkcgo::tag("3")]]*/ size_t EVP_PKEY_get1_encoded_public_key(_EVP_PKEY_PTR pkey, unsigned char **ppub);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_get_bn_param(const _EVP_PKEY_PTR pkey, const char *key_name, _BIGNUM_PTR *bn);
/*[[mkcgo::tag("legacy_1")]]*/ _RSA_PTR RSA_new(void);
/*[[mkcgo::tag("legacy_1")]]*/ void RSA_free(_RSA_PTR arg0);
/*[[mkcgo::tag("legacy_1")]]*/ int RSA_set0_factors(_RSA_PTR rsa, _BIGNUM_PTR p, _BIGNUM_PTR q);
/*[[mkcgo::tag("legacy_1")]]*/ int RSA_set0_crt_params(_RSA_PTR rsa, _BIGNUM_PTR dmp1, _BIGNUM_PTR dmp2, _BIGNUM_PTR iqmp);
/*[[mkcgo::tag("legacy_1")]]*/ void RSA_get0_crt_params(const _RSA_PTR r, const _BIGNUM_PTR *dmp1, const _BIGNUM_PTR *dmq1, const _BIGNUM_PTR *iqmp);
/*[[mkcgo::tag("legacy_1")]]*/ int RSA_set0_key(_RSA_PTR r, _BIGNUM_PTR n, _BIGNUM_PTR e, _BIGNUM_PTR d);
/*[[mkcgo::tag("legacy_1")]]*/ void RSA_get0_factors(const _RSA_PTR rsa, const _BIGNUM_PTR *p, const _BIGNUM_PTR *q);
/*[[mkcgo::tag("legacy_1")]]*/ void RSA_get0_key(const _RSA_PTR rsa, const _BIGNUM_PTR *n, const _BIGNUM_PTR *e, const _BIGNUM_PTR *d);
/*[[mkcgo]]*/ _BIGNUM_PTR BN_new(void);
/*[[mkcgo]]*/ void BN_free(_BIGNUM_PTR arg0);
/*[[mkcgo]]*/ void BN_clear(_BIGNUM_PTR arg0);
/*[[mkcgo]]*/ void BN_clear_free(_BIGNUM_PTR arg0);
/*[[mkcgo]]*/ int BN_num_bits(const _BIGNUM_PTR arg0);
/*[[mkcgo]]*/ _BIGNUM_PTR BN_bin2bn(const unsigned char *arg0, int arg1, _BIGNUM_PTR arg2);
/*[[mkcgo]]*/ _BIGNUM_PTR BN_lebin2bn(const unsigned char *s, int len, _BIGNUM_PTR ret);
/*[[mkcgo]]*/ int BN_bn2lebinpad(const _BIGNUM_PTR a, unsigned char *to, int tolen);
/*[[mkcgo]]*/ int BN_bn2binpad(const _BIGNUM_PTR a, unsigned char *to, int tolen);
/*[[mkcgo::tag("legacy_1")]]*/ int EC_KEY_set_public_key_affine_coordinates(_EC_KEY_PTR key, _BIGNUM_PTR x, _BIGNUM_PTR y);
/*[[mkcgo::tag("legacy_1")]]*/ int EC_KEY_set_public_key(_EC_KEY_PTR key, const _EC_POINT_PTR pub);
/*[[mkcgo::tag("legacy_1")]]*/ void EC_KEY_free(_EC_KEY_PTR arg0);
/*[[mkcgo::tag("legacy_1")]]*/ const _EC_GROUP_PTR EC_KEY_get0_group(const _EC_KEY_PTR arg0);
/*[[mkcgo::tag("legacy_1")]]*/ const _BIGNUM_PTR EC_KEY_get0_private_key(const _EC_KEY_PTR arg0);
/*[[mkcgo::tag("legacy_1")]]*/ const _EC_POINT_PTR EC_KEY_get0_public_key(const _EC_KEY_PTR arg0);
/*[[mkcgo::tag("legacy_1")]]*/ _EC_KEY_PTR EC_KEY_new_by_curve_name(int arg0);
/*[[mkcgo::tag("legacy_1")]]*/ int EC_KEY_set_private_key(_EC_KEY_PTR arg0, const _BIGNUM_PTR arg1);
/*[[mkcgo::tag("legacy_1")]]*/ int EC_KEY_check_key(const _EC_KEY_PTR key);
/*[[mkcgo]]*/ _EC_POINT_PTR EC_POINT_new(const _EC_GROUP_PTR arg0);
/*[[mkcgo]]*/ void EC_POINT_free(_EC_POINT_PTR arg0);
/*[[mkcgo]]*/ int EC_POINT_mul(const _EC_GROUP_PTR group, _EC_POINT_PTR r, const _BIGNUM_PTR n, const _EC_POINT_PTR q, const _BIGNUM_PTR m, _BN_CTX_PTR ctx);
/*[[mkcgo::tag("legacy_1")]]*/ int EC_POINT_get_affine_coordinates_GFp(const _EC_GROUP_PTR arg0, const _EC_POINT_PTR arg1, _BIGNUM_PTR arg2, _BIGNUM_PTR arg3, _BN_CTX_PTR arg4);
/*[[mkcgo::tag("3")]]*/ int EC_POINT_set_affine_coordinates(const _EC_GROUP_PTR arg0, _EC_POINT_PTR arg1, const _BIGNUM_PTR arg2, const _BIGNUM_PTR arg3, _BN_CTX_PTR arg4);
/*[[mkcgo]]*/ size_t EC_POINT_point2oct(const _EC_GROUP_PTR group, const _EC_POINT_PTR p, point_conversion_form_t form, unsigned char *buf, size_t len, _BN_CTX_PTR ctx);
/*[[mkcgo]]*/ int EC_POINT_oct2point(const _EC_GROUP_PTR group, _EC_POINT_PTR p, const unsigned char *buf, size_t len, _BN_CTX_PTR ctx);
/*[[mkcgo]]*/ const char *OBJ_nid2sn(int n);
/*[[mkcgo]]*/ _EC_GROUP_PTR EC_GROUP_new_by_curve_name(int nid);
/*[[mkcgo]]*/ void EC_GROUP_free(_EC_GROUP_PTR group);
/*[[mkcgo::tag("3")]]*/ _EVP_MAC_PTR EVP_MAC_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);
/*[[mkcgo::tag("3")]]*/ _EVP_MAC_CTX_PTR EVP_MAC_CTX_new(_EVP_MAC_PTR arg0);
/*[[mkcgo::tag("3")]]*/ int EVP_MAC_CTX_set_params(_EVP_MAC_CTX_PTR ctx, const _OSSL_PARAM_PTR params);
/*[[mkcgo::tag("3")]]*/ void EVP_MAC_CTX_free(_EVP_MAC_CTX_PTR arg0);
/*[[mkcgo::tag("3")]]*/ _EVP_MAC_CTX_PTR EVP_MAC_CTX_dup(const _EVP_MAC_CTX_PTR arg0);
/*[[mkcgo::tag("3")]]*/ int EVP_MAC_init(_EVP_MAC_CTX_PTR ctx, const unsigned char *key, size_t keylen, const _OSSL_PARAM_PTR params);
/*[[mkcgo::tag("3")]]*/ int EVP_MAC_update(_EVP_MAC_CTX_PTR ctx, const unsigned char *data, size_t datalen);
/*[[mkcgo::tag("3")]]*/ int EVP_MAC_final(_EVP_MAC_CTX_PTR ctx, unsigned char *out, size_t *outl, size_t outsize);
/*[[mkcgo::tag("3")]]*/ void OSSL_PARAM_free(_OSSL_PARAM_PTR p);
/*[[mkcgo::tag("3")]]*/ _OSSL_PARAM_BLD_PTR OSSL_PARAM_BLD_new(void);
/*[[mkcgo::tag("3")]]*/ void OSSL_PARAM_BLD_free(_OSSL_PARAM_BLD_PTR bld);
/*[[mkcgo::tag("3")]]*/ _OSSL_PARAM_PTR OSSL_PARAM_BLD_to_param(_OSSL_PARAM_BLD_PTR bld);
/*[[mkcgo::tag("3")]]*/ int OSSL_PARAM_BLD_push_utf8_string(_OSSL_PARAM_BLD_PTR bld, const char *key, const char *buf, size_t bsize);
/*[[mkcgo::tag("3")]]*/ int OSSL_PARAM_BLD_push_octet_string(_OSSL_PARAM_BLD_PTR bld, const char *key, const void *buf, size_t bsize);
/*[[mkcgo::tag("3")]]*/ int OSSL_PARAM_BLD_push_BN(_OSSL_PARAM_BLD_PTR bld, const char *key, const _BIGNUM_PTR bn);
/*[[mkcgo::tag("3")]]*/ int OSSL_PARAM_BLD_push_int32(_OSSL_PARAM_BLD_PTR bld, const char *key, int32_t num);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_CTX_set_hkdf_mode(_EVP_PKEY_CTX_PTR arg0, int arg1);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_CTX_set_hkdf_md(_EVP_PKEY_CTX_PTR arg0, const _EVP_MD_PTR arg1);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_CTX_set1_hkdf_salt(_EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_CTX_set1_hkdf_key(_EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_CTX_add1_hkdf_info(_EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_up_ref(_EVP_PKEY_PTR key);
/*[[mkcgo::tag("legacy_1")]]*/ int EVP_PKEY_set1_EC_KEY(_EVP_PKEY_PTR pkey, _EC_KEY_PTR key);
/*[[mkcgo::tag("3")]]*/ int EVP_PKEY_CTX_set0_rsa_oaep_label(_EVP_PKEY_CTX_PTR ctx, void *label, int len);
/*[[mkcgo]]*/ int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const _EVP_MD_PTR digest, int keylen, unsigned char *out);
/*[[mkcgo::tag("111")]]*/ int EVP_PKEY_get_raw_public_key(const _EVP_PKEY_PTR pkey, unsigned char *pub, size_t *len);
/*[[mkcgo::tag("111")]]*/ int EVP_PKEY_get_raw_private_key(const _EVP_PKEY_PTR pkey, unsigned char *priv, size_t *len);
/*[[mkcgo::tag("3")]]*/ _EVP_SIGNATURE_PTR EVP_SIGNATURE_fetch(_OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);
/*[[mkcgo::tag("3")]]*/ void EVP_SIGNATURE_free(_EVP_SIGNATURE_PTR signature);
/*[[mkcgo::tag("legacy_1")]]*/ _DSA_PTR DSA_new(void);
/*[[mkcgo::tag("legacy_1")]]*/ void DSA_free(_DSA_PTR r);
/*[[mkcgo::tag("legacy_1")]]*/ int DSA_generate_key(_DSA_PTR a);
/*[[mkcgo::tag("legacy_1")]]*/ void DSA_get0_pqg(const _DSA_PTR d, const _BIGNUM_PTR *p, const _BIGNUM_PTR *q, const _BIGNUM_PTR *g);
/*[[mkcgo::tag("legacy_1")]]*/ int DSA_set0_pqg(_DSA_PTR d, _BIGNUM_PTR p, _BIGNUM_PTR q, _BIGNUM_PTR g);
/*[[mkcgo::tag("legacy_1")]]*/ void DSA_get0_key(const _DSA_PTR d, const _BIGNUM_PTR *pub_key, const _BIGNUM_PTR *priv_key);
/*[[mkcgo::tag("legacy_1")]]*/ int DSA_set0_key(_DSA_PTR d, _BIGNUM_PTR pub_key, _BIGNUM_PTR priv_key);
/*[[mkcgo::tag("3")]]*/ _EVP_KDF_PTR EVP_KDF_fetch(_OSSL_LIB_CTX_PTR libctx, const char *algorithm, const char *properties);
/*[[mkcgo::tag("3")]]*/ void EVP_KDF_free(_EVP_KDF_PTR kdf);
/*[[mkcgo::tag("3")]]*/ _EVP_KDF_CTX_PTR EVP_KDF_CTX_new(_EVP_KDF_PTR kdf);
/*[[mkcgo::tag("3")]]*/ int EVP_KDF_CTX_set_params(_EVP_KDF_CTX_PTR ctx, const _OSSL_PARAM_PTR params);
/*[[mkcgo::tag("3")]]*/ void EVP_KDF_CTX_free(_EVP_KDF_CTX_PTR ctx);
/*[[mkcgo::tag("3")]]*/ size_t EVP_KDF_CTX_get_kdf_size(_EVP_KDF_CTX_PTR ctx);
/*[[mkcgo::tag("3")]]*/ int EVP_KDF_derive(_EVP_KDF_CTX_PTR ctx, unsigned char *key, size_t keylen, const _OSSL_PARAM_PTR params);

