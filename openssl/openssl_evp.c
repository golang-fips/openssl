// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goopenssl.h"

int _goboringcrypto_EVP_sign(EVP_MD *md, EVP_PKEY_CTX *ctx, const uint8_t *msg,
                             size_t msgLen, uint8_t *sig, size_t *slen,
                             EVP_PKEY *key) {
  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;

  if (!(mdctx = _goboringcrypto_EVP_MD_CTX_create()))
    goto err;

  if (1 != _goboringcrypto_EVP_DigestSignInit(mdctx, &ctx, md, NULL, key))
    goto err;

  if (1 != _goboringcrypto_EVP_DigestUpdate(mdctx, msg, msgLen))
    goto err;

  /* Obtain the signature length */
  if (1 != _goboringcrypto_EVP_DigestSignFinal(mdctx, NULL, slen))
    goto err;
  /* Obtain the signature */
  if (1 != _goboringcrypto_EVP_DigestSignFinal(mdctx, sig, slen))
    goto err;

  /* Success */
  ret = 1;

err:
  if (mdctx)
    _goboringcrypto_EVP_MD_CTX_free(mdctx);

  return ret;
}

int _goboringcrypto_EVP_sign_raw(EVP_MD *md, EVP_PKEY_CTX *ctx, const uint8_t *msg,
                             size_t msgLen, uint8_t *sig, size_t *slen,
                             GO_RSA *rsa_key) {
  int ret = 0;
  GO_EVP_PKEY *pk = _goboringcrypto_EVP_PKEY_new();
  _goboringcrypto_EVP_PKEY_assign_RSA(pk, rsa_key);

  if (!ctx && !(ctx = _goboringcrypto_EVP_PKEY_CTX_new(pk, NULL)))
    goto err;

  if (1 != _goboringcrypto_EVP_PKEY_sign_init(ctx))
    goto err;

  if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    goto err;

  if (1 != _goboringcrypto_EVP_PKEY_sign(ctx, sig, slen, msg, msgLen))
    goto err;

  /* Success */
  ret = 1;

err:
  if (ctx)
    _goboringcrypto_EVP_PKEY_CTX_free(ctx);

  return ret;
}

int _goboringcrypto_EVP_verify(EVP_MD *md, EVP_PKEY_CTX *ctx,
                               const uint8_t *msg, size_t msgLen,
                               const uint8_t *sig, unsigned int slen,
                               EVP_PKEY *key) {
  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;

  if (!(mdctx = _goboringcrypto_EVP_MD_CTX_create()))
    goto err;
  if (1 != _goboringcrypto_EVP_DigestVerifyInit(mdctx, &ctx, md, NULL, key))
    goto err;

  if (1 != _goboringcrypto_EVP_DigestUpdate(mdctx, msg, msgLen))
    goto err;

  if (1 != _goboringcrypto_EVP_DigestVerifyFinal(mdctx, sig, slen)) {
    goto err;
  }

  /* Success */
  ret = 1;

err:
  if (mdctx)
    _goboringcrypto_EVP_MD_CTX_free(mdctx);

  return ret;
}

int _goboringcrypto_EVP_verify_raw(const uint8_t *msg, size_t msgLen,
                               const uint8_t *sig, unsigned int slen,
                               GO_RSA *rsa_key) {

  int ret = 0;
  EVP_PKEY_CTX *ctx;
  GO_EVP_PKEY *pk = _goboringcrypto_EVP_PKEY_new();
  _goboringcrypto_EVP_PKEY_assign_RSA(pk, rsa_key);

  if (!(ctx = _goboringcrypto_EVP_PKEY_CTX_new(pk, NULL)))
    goto err;

  if (1 != _goboringcrypto_EVP_PKEY_verify_init(ctx))
    goto err;

  if (_goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    goto err;

  if (1 != _goboringcrypto_EVP_PKEY_verify(ctx, sig, slen, msg, msgLen))
    goto err;

  /* Success */
  ret = 1;

err:
  if (ctx)
    _goboringcrypto_EVP_PKEY_CTX_free(ctx);

  return ret;
}
