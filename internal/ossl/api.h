//mkcgo:failCondition retval != 1

#include "ossl.h"
#include <stdint.h>
#include <stddef.h>

void ERR_clear_error(void);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
unsigned long ERR_get_error_line(const char **file, int *line);
unsigned long ERR_get_error_all(const char **file, int *line,
                                const char **fn,
                                const char **data, int *flags);
void ERR_load_crypto_strings(void);
/*[[mkcgo::c_only]]*/ void ERR_remove_thread_state(const CRYPTO_THREADID_PTR tid);

/*[[mkcgo::c_only]]*/ int CRYPTO_num_locks(void);
/*[[mkcgo::c_only]]*/ int CRYPTO_THREADID_set_callback(threadid_func fn);
/*[[mkcgo::c_only]]*/ void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID_PTR id, unsigned long val);
/*[[mkcgo::c_only]]*/ void CRYPTO_set_locking_callback(locking_func fn);

/*[[mkcgo::name("_SSLeay_version")]]*/ const char *SSLeay_version(int typ);
/*[[mkcgo::name("_OpenSSL_version")]]*/ const char *OpenSSL_version(int typ);
void OPENSSL_init(void);
void OPENSSL_add_all_algorithms_conf(void);
/*[[mkcgo::error_only]]*/ int OPENSSL_init_crypto(uint64_t ops, const OPENSSL_INIT_SETTINGS_PTR settings);

void *CRYPTO_malloc(size_t num, const char *file, int line);
void CRYPTO_free(void *str, const char *file, int line);

int FIPS_mode(void);
/*[[mkcgo::error_only]]*/ int FIPS_mode_set(int r);

int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX_PTR libctx);
/*[[mkcgo::error_only]]*/ int EVP_default_properties_enable_fips(OSSL_LIB_CTX_PTR libctx, int enable);

/*[[mkcgo::error_only]]*/ int RAND_bytes(unsigned char *buf, int num);

EVP_CIPHER_PTR EVP_aes_128_gcm(void);
EVP_CIPHER_PTR EVP_aes_192_gcm(void);
EVP_CIPHER_PTR EVP_aes_256_gcm(void);
EVP_CIPHER_PTR EVP_aes_128_cbc(void);
EVP_CIPHER_PTR EVP_aes_192_cbc(void);
EVP_CIPHER_PTR EVP_aes_256_cbc(void);
EVP_CIPHER_PTR EVP_aes_128_ctr(void);
EVP_CIPHER_PTR EVP_aes_192_ctr(void);
EVP_CIPHER_PTR EVP_aes_256_ctr(void);
EVP_CIPHER_PTR EVP_aes_128_ecb(void);
EVP_CIPHER_PTR EVP_aes_192_ecb(void);
EVP_CIPHER_PTR EVP_aes_256_ecb(void);
EVP_CIPHER_PTR EVP_des_cbc(void);
EVP_CIPHER_PTR EVP_des_ecb(void);
EVP_CIPHER_PTR EVP_des_ede3_cbc(void);
EVP_CIPHER_PTR EVP_des_ede3_ecb(void);
EVP_CIPHER_PTR EVP_rc4(void);

/*[[mkcgo::error]]*/ EVP_CIPHER_PTR EVP_CIPHER_fetch(OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);
/*[[mkcgo::error]]*/ EVP_CIPHER_CTX_PTR EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX_PTR ctx, int cmd, int p1, void *p2);
/*[[mkcgo::error_only]]*/ int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX_PTR x, int padding);
/*[[mkcgo::name("_EVP_CIPHER_block_size")]]*/ int EVP_CIPHER_block_size(const EVP_CIPHER_PTR e);
/*[[mkcgo::name("_EVP_CIPHER_get_block_size")]]*/ int EVP_CIPHER_get_block_size(const EVP_CIPHER_PTR e);
const char *EVP_CIPHER_get0_name(const EVP_CIPHER_PTR cipher);
/*[[mkcgo::error_only]]*/ int EVP_CipherInit_ex(EVP_CIPHER_CTX_PTR ctx, const EVP_CIPHER_PTR typ, ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv, int enc);
/*[[mkcgo::error_only]]*/ int EVP_CipherUpdate(EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
/*[[mkcgo::error_only]]*/ int EVP_EncryptInit_ex(EVP_CIPHER_CTX_PTR ctx, const EVP_CIPHER_PTR typ, ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv);
/*[[mkcgo::error_only]]*/ int EVP_EncryptUpdate(EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
/*[[mkcgo::error_only]]*/ int EVP_EncryptFinal_ex(EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl);
/*[[mkcgo::error_only]]*/ int EVP_DecryptInit_ex(EVP_CIPHER_CTX_PTR ctx, const EVP_CIPHER_PTR typ, ENGINE_PTR impl, const unsigned char *key, const unsigned char *iv);
/*[[mkcgo::error_only]]*/ int EVP_DecryptUpdate(EVP_CIPHER_CTX_PTR ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
/*[[mkcgo::error_only]]*/ int EVP_DecryptFinal_ex(EVP_CIPHER_CTX_PTR ctx, unsigned char *outm, int *outl);
/*[[mkcgo::error_only]]*/ int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX_PTR ctx, int keylen);

void EVP_PKEY_free(EVP_PKEY_PTR key);
/*[[mkcgo::name("_EVP_PKEY_size")]]*/ int EVP_PKEY_size(const EVP_PKEY_PTR pkey);
/*[[mkcgo::name("_EVP_PKEY_get_size")]]*/ int EVP_PKEY_get_size(const EVP_PKEY_PTR pkey);
/*[[mkcgo::name("_EVP_PKEY_bits")]]*/ int EVP_PKEY_bits(const EVP_PKEY_PTR pkey);
/*[[mkcgo::name("_EVP_PKEY_get_bits")]]*/ int EVP_PKEY_get_bits(const EVP_PKEY_PTR pkey);
/*[[mkcgo::error]]*/ EVP_PKEY_PTR EVP_PKEY_new(void);
/*[[mkcgo::error]]*/ EVP_PKEY_PTR EVP_PKEY_new_raw_private_key(int typ, ENGINE_PTR e, const unsigned char *key, size_t keylen);
/*[[mkcgo::error]]*/ EVP_PKEY_PTR EVP_PKEY_new_raw_public_key(int typ, ENGINE_PTR e, const unsigned char *key, size_t keylen);
/*[[mkcgo::error("retval == 0")]]*/ size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY_PTR pkey, unsigned char **ppub);
/*[[mkcgo::error]]*/ RSA_PTR EVP_PKEY_get1_RSA(EVP_PKEY_PTR pkey);
/*[[mkcgo::error]]*/ const DSA_PTR EVP_PKEY_get0_DSA(const EVP_PKEY_PTR pkey);
/*[[mkcgo::error]]*/ const EC_KEY_PTR EVP_PKEY_get0_EC_KEY(const EVP_PKEY_PTR pkey);
/*[[mkcgo::error]]*/ void *EVP_PKEY_get0(const EVP_PKEY_PTR pkey);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_up_ref(EVP_PKEY_PTR key);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_assign(EVP_PKEY_PTR pkey, int typ, void *key);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_get_raw_private_key(const EVP_PKEY_PTR pkey, unsigned char *priv, size_t *len);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_get_raw_public_key(const EVP_PKEY_PTR pkey, unsigned char *pub, size_t *len);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_set1_encoded_public_key(EVP_PKEY_PTR pkey, const unsigned char *pub, size_t publen);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_set1_EC_KEY(EVP_PKEY_PTR pkey, EC_KEY_PTR key);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_get_bn_param(const EVP_PKEY_PTR pkey, const char *key_name, BIGNUM_PTR *bn);

const EVP_MD_PTR EVP_md5_sha1(void);
const EVP_MD_PTR EVP_md4(void);
const EVP_MD_PTR EVP_md5(void);
const EVP_MD_PTR EVP_sha1(void);
const EVP_MD_PTR EVP_sha224(void);
const EVP_MD_PTR EVP_sha256(void);
const EVP_MD_PTR EVP_sha384(void);
const EVP_MD_PTR EVP_sha512(void);
const EVP_MD_PTR EVP_sha3_224(void);
const EVP_MD_PTR EVP_sha3_256(void);
const EVP_MD_PTR EVP_sha3_384(void);
const EVP_MD_PTR EVP_sha3_512(void);

void EC_KEY_free(EC_KEY_PTR arg0);
/*[[mkcgo::error]]*/ const EC_GROUP_PTR EC_KEY_get0_group(const EC_KEY_PTR arg0);
/*[[mkcgo::error]]*/ const BIGNUM_PTR EC_KEY_get0_private_key(const EC_KEY_PTR arg0);
/*[[mkcgo::error]]*/ const EC_POINT_PTR EC_KEY_get0_public_key(const EC_KEY_PTR arg0);
/*[[mkcgo::error]]*/ EC_KEY_PTR EC_KEY_new_by_curve_name(int arg0);
/*[[mkcgo::error_only]]*/ int EC_KEY_set_public_key_affine_coordinates(EC_KEY_PTR key, BIGNUM_PTR x, BIGNUM_PTR y);
/*[[mkcgo::error_only]]*/ int EC_KEY_set_public_key(EC_KEY_PTR key, const EC_POINT_PTR pub);
/*[[mkcgo::error_only]]*/ int EC_KEY_set_private_key(EC_KEY_PTR arg0, const BIGNUM_PTR arg1);

void EVP_PKEY_CTX_free(EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo::error]]*/ EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new(EVP_PKEY_PTR arg0, ENGINE_PTR arg1);
/*[[mkcgo::error]]*/ EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new_id(int id, ENGINE_PTR e);
/*[[mkcgo::error]]*/ EVP_PKEY_CTX_PTR EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX_PTR libctx, EVP_PKEY_PTR pkey, const char *propquery);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX_PTR ctx, int keytype, int optype, int cmd, int p1, void *p2);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_decrypt(EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_encrypt(EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_decrypt_init(EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_encrypt_init(EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_sign_init(EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_verify_init(EVP_PKEY_CTX_PTR arg0);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_verify(EVP_PKEY_CTX_PTR ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_sign(EVP_PKEY_CTX_PTR arg0, unsigned char *arg1, size_t *arg2, const unsigned char *arg3, size_t arg4);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_derive_init(EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX_PTR ctx, EVP_PKEY_PTR peer);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_derive(EVP_PKEY_CTX_PTR ctx, unsigned char *key, size_t *keylen);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_fromdata_init(EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_fromdata(EVP_PKEY_CTX_PTR ctx, EVP_PKEY_PTR *pkey, int selection, OSSL_PARAM_PTR params);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_paramgen_init(EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_paramgen(EVP_PKEY_CTX_PTR ctx, EVP_PKEY_PTR *ppkey);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_keygen_init(EVP_PKEY_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_keygen(EVP_PKEY_CTX_PTR ctx, EVP_PKEY_PTR *ppkey);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX_PTR arg0, int arg1);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX_PTR arg0, const EVP_MD_PTR arg1);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX_PTR arg0, const unsigned char *arg1, int arg2);
/*[[mkcgo::error_only]]*/ int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX_PTR ctx, void *label, int len);
/*[[mkcgo::error]] [[mkcgo::variadic("EVP_PKEY_Q_keygen")]]*/ EVP_PKEY_PTR EVP_PKEY_Q_keygen_ED25519(OSSL_LIB_CTX_PTR ctx, const char *propq, const char *typ);
/*[[mkcgo::error]] [[mkcgo::variadic("EVP_PKEY_Q_keygen")]]*/ EVP_PKEY_PTR EVP_PKEY_Q_keygen_RSA(OSSL_LIB_CTX_PTR ctx, const char *propq, const char *typ, size_t arg1);
/*[[mkcgo::error]] [[mkcgo::variadic("EVP_PKEY_Q_keygen")]]*/ EVP_PKEY_PTR EVP_PKEY_Q_keygen_EC(OSSL_LIB_CTX_PTR ctx, const char *propq, const char *typ, const char *arg1);

void RSA_free(RSA_PTR r);
void RSA_get0_crt_params(const RSA_PTR r, const BIGNUM_PTR *dmp1, const BIGNUM_PTR *dmq1, const BIGNUM_PTR *iqmp);
void RSA_get0_factors(const RSA_PTR r, const BIGNUM_PTR *p, const BIGNUM_PTR *q);
void RSA_get0_key(const RSA_PTR r, const BIGNUM_PTR *n, const BIGNUM_PTR *e, const BIGNUM_PTR *d);
/*[[mkcgo::error]]*/ RSA_PTR RSA_new(void);
/*[[mkcgo::error_only]]*/ int RSA_set0_key(RSA_PTR r, BIGNUM_PTR n, BIGNUM_PTR e, BIGNUM_PTR d);
/*[[mkcgo::error_only]]*/ int RSA_set0_factors(RSA_PTR r, BIGNUM_PTR p, BIGNUM_PTR q);
/*[[mkcgo::error_only]]*/ int RSA_set0_crt_params(RSA_PTR r, BIGNUM_PTR dmp1, BIGNUM_PTR dmq1, BIGNUM_PTR iqmp);

void DSA_free(DSA_PTR r);
void DSA_get0_pqg(const DSA_PTR d, const BIGNUM_PTR *p, const BIGNUM_PTR *q, const BIGNUM_PTR *g);
void DSA_get0_key(const DSA_PTR d, const BIGNUM_PTR *pub_key, const BIGNUM_PTR *priv_key);
/*[[mkcgo::error]]*/ DSA_PTR DSA_new(void);
/*[[mkcgo::error_only]]*/ int DSA_generate_key(DSA_PTR a);
/*[[mkcgo::error_only]]*/ int DSA_set0_pqg(DSA_PTR d, BIGNUM_PTR p, BIGNUM_PTR q, BIGNUM_PTR g);
/*[[mkcgo::error_only]]*/ int DSA_set0_key(DSA_PTR d, BIGNUM_PTR pub_key, BIGNUM_PTR priv_key);

void HMAC_CTX_free(HMAC_CTX_PTR arg0);
void HMAC_CTX_init(HMAC_CTX_PTR arg0);
void HMAC_CTX_cleanup(HMAC_CTX_PTR arg0);
/*[[mkcgo::error]]*/ HMAC_CTX_PTR HMAC_CTX_new(void);
/*[[mkcgo::error_only]]*/ int HMAC_CTX_copy(HMAC_CTX_PTR dest, HMAC_CTX_PTR src);
/*[[mkcgo::error_only]]*/ int HMAC_Init_ex(HMAC_CTX_PTR arg0, const void *arg1, int arg2, const EVP_MD_PTR arg3, ENGINE_PTR arg4);
/*[[mkcgo::error_only]]*/ int HMAC_Update(HMAC_CTX_PTR arg0, const unsigned char *arg1, size_t arg2);
/*[[mkcgo::error_only]]*/ int HMAC_Final(HMAC_CTX_PTR arg0, unsigned char *arg1, unsigned int *arg2);

int OSSL_PROVIDER_available(OSSL_LIB_CTX_PTR libctx, const char *name);
/*[[mkcgo::error]]*/ OSSL_PROVIDER_PTR OSSL_PROVIDER_try_load(OSSL_LIB_CTX_PTR libctx, const char *name, int retain_fallbacks);
const char *OSSL_PROVIDER_get0_name(const OSSL_PROVIDER_PTR prov);

void EVP_MD_free(EVP_MD_PTR md);
const char *EVP_MD_get0_name(const EVP_MD_PTR md);
/*[[mkcgo::name("_EVP_MD_size")]]*/ int EVP_MD_size(const EVP_MD_PTR md);
/*[[mkcgo::name("_EVP_MD_get_size")]]*/ int EVP_MD_get_size(const EVP_MD_PTR md);
/*[[mkcgo::name("_EVP_MD_block_size")]]*/ int EVP_MD_block_size(const EVP_MD_PTR md);
/*[[mkcgo::name("_EVP_MD_get_block_size")]]*/ int EVP_MD_get_block_size(const EVP_MD_PTR md);
/*[[mkcgo::name("_EVP_MD_CTX_destroy")]]*/ void EVP_MD_CTX_destroy(EVP_MD_CTX_PTR ctx);
/*[[mkcgo::name("_EVP_MD_CTX_free")]]*/ void EVP_MD_CTX_free(EVP_MD_CTX_PTR ctx);
/*[[mkcgo::error]] [[mkcgo::name("_EVP_MD_CTX_create")]]*/ EVP_MD_CTX_PTR EVP_MD_CTX_create(void);
/*[[mkcgo::error]] [[mkcgo::name("_EVP_MD_CTX_new")]]*/ EVP_MD_CTX_PTR EVP_MD_CTX_new(void);
/*[[mkcgo::error]]*/ const OSSL_PROVIDER_PTR EVP_MD_get0_provider(const EVP_MD_PTR md);
/*[[mkcgo::error]]*/ EVP_MD_PTR EVP_MD_fetch(OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);
/*[[mkcgo::error_only]]*/ int EVP_MD_CTX_copy(EVP_MD_CTX_PTR out, const EVP_MD_CTX_PTR in);
/*[[mkcgo::error_only]]*/ int EVP_MD_CTX_copy_ex(EVP_MD_CTX_PTR out, const EVP_MD_CTX_PTR in);
/*[[mkcgo::error_only]]*/ int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD_PTR typ, ENGINE_PTR impl);
/*[[mkcgo::error_only]]*/ int EVP_DigestInit_ex(EVP_MD_CTX_PTR ctx, const EVP_MD_PTR typ, ENGINE_PTR impl);
/*[[mkcgo::error_only]]*/ int EVP_DigestInit(EVP_MD_CTX_PTR ctx, const EVP_MD_PTR typ);
/*[[mkcgo::error_only]]*/ int EVP_DigestUpdate(EVP_MD_CTX_PTR ctx, const void *d, size_t cnt);
/*[[mkcgo::error_only]]*/ int EVP_DigestFinal(EVP_MD_CTX_PTR ctx, unsigned char *md, unsigned int *s);
/*[[mkcgo::error_only]]*/ int EVP_DigestSign(EVP_MD_CTX_PTR ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
/*[[mkcgo::error_only]]*/ int EVP_DigestSignInit(EVP_MD_CTX_PTR ctx, EVP_PKEY_CTX_PTR *pctx, const EVP_MD_PTR typ, ENGINE_PTR e, EVP_PKEY_PTR pkey);
/*[[mkcgo::error_only]]*/ int EVP_DigestSignFinal(EVP_MD_CTX_PTR ctx, unsigned char *sig, size_t *siglen);
/*[[mkcgo::error_only]]*/ int EVP_DigestVerifyInit(EVP_MD_CTX_PTR ctx, EVP_PKEY_CTX_PTR *pctx, const EVP_MD_PTR typ, ENGINE_PTR e, EVP_PKEY_PTR pkey);
/*[[mkcgo::error_only]]*/ int EVP_DigestVerifyFinal(EVP_MD_CTX_PTR ctx, const unsigned char *sig, size_t siglen);
/*[[mkcgo::error_only]]*/ int EVP_DigestVerify(EVP_MD_CTX_PTR ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
/*[[mkcgo::error_only]]*/ int MD5_Init(MD5_CTX_PTR c);
/*[[mkcgo::error_only]]*/ int MD5_Update(MD5_CTX_PTR c, const void *data, size_t len);
/*[[mkcgo::error_only]]*/ int MD5_Final(unsigned char *md, MD5_CTX_PTR c);
/*[[mkcgo::error_only]]*/ int SHA1_Init(SHA_CTX_PTR c);
/*[[mkcgo::error_only]]*/ int SHA1_Update(SHA_CTX_PTR c, const void *data, size_t len);
/*[[mkcgo::error_only]]*/ int SHA1_Final(unsigned char *md, SHA_CTX_PTR c);

void BN_free(BIGNUM_PTR arg0);
void BN_clear(BIGNUM_PTR arg0);
void BN_clear_free(BIGNUM_PTR arg0);
int BN_num_bits(const BIGNUM_PTR arg0);
int BN_bn2bin(const BIGNUM_PTR a, unsigned char *to);
/*[[mkcgo::error]]*/ BIGNUM_PTR BN_new(void);
/*[[mkcgo::error]]*/ BIGNUM_PTR BN_bin2bn(const unsigned char *arg0, int arg1, BIGNUM_PTR arg2);
/*[[mkcgo::error]] [[mkcgo::name("BN_expand2")]]*/ BIGNUM_PTR bn_expand2(BIGNUM_PTR a, int n);
/*[[mkcgo::error]]*/ BIGNUM_PTR BN_lebin2bn(const unsigned char *s, int len, BIGNUM_PTR ret);
/*[[mkcgo::error("retval == -1")]]*/ int BN_bn2lebinpad(const BIGNUM_PTR a, unsigned char *to, int tolen);
/*[[mkcgo::error("retval == -1")]]*/ int BN_bn2binpad(const BIGNUM_PTR a, unsigned char *to, int tolen);


void EC_POINT_free(EC_POINT_PTR arg0);
/*[[mkcgo::error]]*/ EC_POINT_PTR EC_POINT_new(const EC_GROUP_PTR arg0);
/*[[mkcgo::error("retval == 0")]]*/ size_t EC_POINT_point2oct(const EC_GROUP_PTR group, const EC_POINT_PTR p, point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EC_POINT_mul(const EC_GROUP_PTR group, EC_POINT_PTR r, const BIGNUM_PTR n, const EC_POINT_PTR q, const BIGNUM_PTR m, BN_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP_PTR arg0, const EC_POINT_PTR arg1, BIGNUM_PTR arg2, BIGNUM_PTR arg3, BN_CTX_PTR arg4);
/*[[mkcgo::error_only]]*/ int EC_POINT_set_affine_coordinates(const EC_GROUP_PTR arg0, EC_POINT_PTR arg1, const BIGNUM_PTR arg2, const BIGNUM_PTR arg3, BN_CTX_PTR arg4);
/*[[mkcgo::error_only]]*/ int EC_POINT_oct2point(const EC_GROUP_PTR group, EC_POINT_PTR p, const unsigned char *buf, size_t len, BN_CTX_PTR ctx);

const char *OBJ_nid2sn(int n);

/*[[mkcgo::error]]*/ EC_GROUP_PTR EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP_PTR group);

void EVP_MAC_CTX_free(EVP_MAC_CTX_PTR arg0);
/*[[mkcgo::error]]*/ EVP_MAC_PTR EVP_MAC_fetch(OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);
/*[[mkcgo::error]]*/ EVP_MAC_CTX_PTR EVP_MAC_CTX_new(EVP_MAC_PTR arg0);
/*[[mkcgo::error]]*/ EVP_MAC_CTX_PTR EVP_MAC_CTX_dup(const EVP_MAC_CTX_PTR arg0);
/*[[mkcgo::error_only]]*/ int EVP_MAC_CTX_set_params(EVP_MAC_CTX_PTR ctx, const OSSL_PARAM_PTR params);
/*[[mkcgo::error_only]]*/ int EVP_MAC_init(EVP_MAC_CTX_PTR ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM_PTR params);
/*[[mkcgo::error_only]]*/ int EVP_MAC_update(EVP_MAC_CTX_PTR ctx, const unsigned char *data, size_t datalen);
/*[[mkcgo::error_only]]*/ int EVP_MAC_final(EVP_MAC_CTX_PTR ctx, unsigned char *out, size_t *outl, size_t outsize);

void OSSL_PARAM_free(OSSL_PARAM_PTR p);

void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD_PTR bld);
/*[[mkcgo::error]]*/ OSSL_PARAM_BLD_PTR OSSL_PARAM_BLD_new(void);
/*[[mkcgo::error]]*/ OSSL_PARAM_PTR OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD_PTR bld);
/*[[mkcgo::error_only]]*/ int OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD_PTR bld, const char *key, const char *buf, size_t bsize);
/*[[mkcgo::error_only]]*/ int OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD_PTR bld, const char *key, const void *buf, size_t bsize);
/*[[mkcgo::error_only]]*/ int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD_PTR bld, const char *key, const BIGNUM_PTR bn);
/*[[mkcgo::error_only]]*/ int OSSL_PARAM_BLD_push_int32(OSSL_PARAM_BLD_PTR bld, const char *key, int32_t num);

/*[[mkcgo::error_only]]*/ int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD_PTR digest, int keylen, unsigned char *out);

void EVP_SIGNATURE_free(EVP_SIGNATURE_PTR signature);
/*[[mkcgo::error]]*/ EVP_SIGNATURE_PTR EVP_SIGNATURE_fetch(OSSL_LIB_CTX_PTR ctx, const char *algorithm, const char *properties);

void EVP_KDF_free(EVP_KDF_PTR kdf);
/*[[mkcgo::error]]*/ EVP_KDF_CTX_PTR EVP_KDF_CTX_new(EVP_KDF_PTR kdf);
/*[[mkcgo::error]]*/ EVP_KDF_PTR EVP_KDF_fetch(OSSL_LIB_CTX_PTR libctx, const char *algorithm, const char *properties);

void EVP_KDF_CTX_free(EVP_KDF_CTX_PTR ctx);
/*[[mkcgo::error("retval == 0")]]*/ size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX_PTR ctx);
/*[[mkcgo::error_only]]*/ int EVP_KDF_CTX_set_params(EVP_KDF_CTX_PTR ctx, const OSSL_PARAM_PTR params);
/*[[mkcgo::error_only]]*/ int EVP_KDF_derive(EVP_KDF_CTX_PTR ctx, unsigned char *key, size_t keylen, const OSSL_PARAM_PTR params);

