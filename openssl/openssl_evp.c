// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goopenssl.h"
#include <assert.h>

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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
DEFINEFUNCINTERNAL(int, EVP_PKEY_up_ref, (GO_EVP_PKEY *pkey), (pkey))

GO_EVP_PKEY *
_goboringcrypto_EVP_PKEY_ref(GO_EVP_PKEY *pkey)
{
  if (_goboringcrypto_internal_EVP_PKEY_up_ref(pkey) != 1)
    return NULL;

  return pkey;
}

#else
GO_EVP_PKEY *
_goboringcrypto_EVP_PKEY_ref(GO_EVP_PKEY *pkey)
{
  GO_EVP_PKEY *result = NULL;

  if (pkey->type != EVP_PKEY_EC && pkey->type != EVP_PKEY_RSA)
    return NULL;

  result = _goboringcrypto_EVP_PKEY_new();
  if (!result)
    goto err;

  switch (pkey->type) {
  case EVP_PKEY_EC:
    if (_goboringcrypto_EVP_PKEY_assign_EC_KEY(result, _goboringcrypto_EVP_PKEY_get1_EC_KEY(pkey)) != 1)
      goto err;
    break;

  case EVP_PKEY_RSA:
    if (_goboringcrypto_EVP_PKEY_assign_RSA(result, _goboringcrypto_EVP_PKEY_get1_RSA(pkey)) != 1)
      goto err;

    break;

  default:
    assert(0);
  }

  return result;

err:
  _goboringcrypto_EVP_PKEY_free(result);
  return NULL;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
DEFINEFUNCINTERNAL(const GO_EC_KEY *, EVP_PKEY_get0_EC_KEY, (const GO_EVP_PKEY *pkey), (pkey));

const GO_EC_KEY *
_goboringcrypto_EVP_PKEY_get0_EC_KEY(const GO_EVP_PKEY *pkey)
{
  return _goboringcrypto_internal_EVP_PKEY_get0_EC_KEY(pkey);
}
#else
DEFINEFUNCINTERNAL(void *, EVP_PKEY_get0, (EVP_PKEY *pkey), (pkey))

const GO_EC_KEY *
_goboringcrypto_EVP_PKEY_get0_EC_KEY(const GO_EVP_PKEY *pkey)
{
  return (const GO_EC_KEY *)_goboringcrypto_internal_EVP_PKEY_get0((EVP_PKEY *)pkey);
}
#endif
