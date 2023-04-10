// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goopenssl.h"

// Only in BoringSSL.
GO_EC_KEY *_goboringcrypto_EC_KEY_generate_key_fips(int nid) {
  GO_EVP_PKEY_CTX *ctx = NULL;
  GO_EVP_PKEY *pkey = NULL;
  GO_BIGNUM *e = NULL;
  GO_EC_KEY *ret = NULL;

  ctx = _goboringcrypto_EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ctx)
    return NULL;

  if (_goboringcrypto_EVP_PKEY_keygen_init(ctx) <= 0)
    goto err;

  if (_goboringcrypto_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0)
    goto err;

  if (_goboringcrypto_EVP_PKEY_keygen(ctx, &pkey) <= 0)
    goto err;

  ret = _goboringcrypto_EVP_PKEY_get1_EC_KEY(pkey);

err:
  _goboringcrypto_EVP_PKEY_free(pkey);
  _goboringcrypto_EVP_PKEY_CTX_free(ctx);
  return ret;
}

int _goboringcrypto_ECDSA_sign(EVP_MD *md, const uint8_t *msg, size_t msgLen,
                               uint8_t *sig, size_t *slen,
                               GO_EC_KEY *eckey) {
  int result;
  EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
  if (!key) {
    return 0;
  }
  if (!_goboringcrypto_EVP_PKEY_set1_EC_KEY(key, eckey)) {
    result = 0;
    goto err;
  }
  result = _goboringcrypto_EVP_sign(md, NULL, msg, msgLen, sig, slen, key);
err:
  _goboringcrypto_EVP_PKEY_free(key);
  return result;
}

int _goboringcrypto_ECDSA_verify(EVP_MD *md, const uint8_t *msg, size_t msgLen,
                                 const uint8_t *sig, unsigned int slen,
                                 GO_EC_KEY *eckey) {

  int result;
  EVP_PKEY *key = _goboringcrypto_EVP_PKEY_new();
  if (!key) {
    return 0;
  }
  if (!_goboringcrypto_EVP_PKEY_set1_EC_KEY(key, eckey)) {
    result = 0;
    goto err;
  }

  result = _goboringcrypto_EVP_verify(md, NULL, msg, msgLen, sig, slen, key);

err:
  _goboringcrypto_EVP_PKEY_free(key);
  return result;
}

int _goboringcrypto_ECDSA_sign_raw(EVP_MD *md, const uint8_t *msg,
				   size_t msgLen, uint8_t *sig, size_t *slen,
				   GO_EC_KEY *ec_key) {
  int ret = 0;
  GO_EVP_PKEY_CTX *ctx = NULL;
  GO_EVP_PKEY *pkey = NULL;

  pkey = _goboringcrypto_EVP_PKEY_new();
  if (!pkey)
    goto err;

  if (_goboringcrypto_EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1)
    goto err;

  ctx = _goboringcrypto_EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx)
    goto err;

  if (_goboringcrypto_EVP_PKEY_sign_init(ctx) != 1)
    goto err;

  if (md && _goboringcrypto_EVP_PKEY_CTX_set_signature_md(ctx, md) != 1)
    goto err;

  if (_goboringcrypto_EVP_PKEY_sign(ctx, sig, slen, msg, msgLen) != 1)
    goto err;

  /* Success */
  ret = 1;

err:
  _goboringcrypto_EVP_PKEY_CTX_free(ctx);
  _goboringcrypto_EVP_PKEY_free(pkey);

  return ret;
}

int _goboringcrypto_ECDSA_verify_raw(EVP_MD *md,
				     const uint8_t *msg, size_t msgLen,
				     const uint8_t *sig, unsigned int slen,
				     GO_EC_KEY *ec_key) {
  int ret = 0;
  GO_EVP_PKEY_CTX *ctx = NULL;
  GO_EVP_PKEY *pkey = NULL;

  pkey = _goboringcrypto_EVP_PKEY_new();
  if (!pkey)
    goto err;

  if (_goboringcrypto_EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1)
    goto err;

  ctx = _goboringcrypto_EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx)
    goto err;

  if (_goboringcrypto_EVP_PKEY_verify_init(ctx) != 1)
    goto err;

  if (md && _goboringcrypto_EVP_PKEY_CTX_set_signature_md(ctx, md) != 1)
    goto err;

  if (_goboringcrypto_EVP_PKEY_verify(ctx, sig, slen, msg, msgLen) != 1)
    goto err;

  /* Success */
  ret = 1;

err:
  _goboringcrypto_EVP_PKEY_CTX_free(ctx);
  _goboringcrypto_EVP_PKEY_free(pkey);

  return ret;
}
