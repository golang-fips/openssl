// This file contains HMAC portability wrappers.
// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goopenssl.h"

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0

DEFINEFUNCINTERNAL(EVP_PKEY *,
		   EVP_PKEY_new_mac_key,
		   (int type, ENGINE *e, const unsigned char *key, int keylen),
		   (type, e, key, keylen))
DEFINEFUNCINTERNAL(int, EVP_MD_CTX_reset, (EVP_MD_CTX *ctx), (ctx))

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_3_0_0
DEFINEFUNCINTERNAL(const EVP_MD *, EVP_MD_CTX_get0_md, (const EVP_MD_CTX *ctx), (ctx))
#else
DEFINEFUNCINTERNAL(const EVP_MD *, EVP_MD_CTX_md, (const EVP_MD_CTX *ctx), (ctx))
#endif
DEFINEFUNCINTERNAL(int, EVP_MD_CTX_copy_ex, (EVP_MD_CTX *out, const EVP_MD_CTX *in), (out, in))

/* EVP_DigestSignUpdate is converted from a macro in 3.0 */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_3_0_0
DEFINEFUNCINTERNAL(int, EVP_DigestSignUpdate,
		   (EVP_MD_CTX* ctx, const void *d, size_t cnt),
		   (ctx, d, cnt))
#endif

struct go_hmac_ctx {
  EVP_PKEY *pkey;
  EVP_MD_CTX *mdctx;
};

GO_HMAC_CTX *
_goboringcrypto_HMAC_CTX_new(const unsigned char *key, int keylen,
			     const EVP_MD *md)
{
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *mdctx = NULL;
  struct go_hmac_ctx *ctx;

  pkey = _goboringcrypto_internal_EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL,
						       key, keylen);
  if (!pkey)
    return NULL;

  mdctx = _goboringcrypto_EVP_MD_CTX_create();
  if (mdctx == NULL)
    goto err;

  if (_goboringcrypto_EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) != 1)
    goto err;

  ctx = malloc(sizeof(*ctx));
  if (!ctx)
    goto err;

  ctx->pkey = pkey;
  ctx->mdctx = mdctx;

  return ctx;

 err:
  _goboringcrypto_EVP_PKEY_free(pkey);
  _goboringcrypto_EVP_MD_CTX_free(mdctx);
  return NULL;
}

int _goboringcrypto_HMAC_Update(GO_HMAC_CTX *ctx,
				const unsigned char *data, size_t len)
{
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_3_0_0
  return _goboringcrypto_internal_EVP_DigestSignUpdate(ctx->mdctx, data, len);
#else
  return _goboringcrypto_EVP_DigestUpdate(ctx->mdctx, data, len);
#endif
}

int _goboringcrypto_HMAC_CTX_reset(GO_HMAC_CTX *ctx)
{
  int ret;
  const EVP_MD *md;


#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_3_0_0
  md = _goboringcrypto_internal_EVP_MD_CTX_get0_md(ctx->mdctx);
#else
  md = _goboringcrypto_internal_EVP_MD_CTX_md(ctx->mdctx);
#endif

  if (!md)
    return -1;

  ret = _goboringcrypto_internal_EVP_MD_CTX_reset(ctx->mdctx);
  if (ret != 1)
    return ret;

  ret = _goboringcrypto_EVP_DigestSignInit(ctx->mdctx, NULL, md, NULL, ctx->pkey);
  if (ret != 1)
    return ret;

  return 1;
}

void _goboringcrypto_HMAC_CTX_free(GO_HMAC_CTX *ctx)
{
  if (ctx) {
    _goboringcrypto_EVP_PKEY_free(ctx->pkey);
    _goboringcrypto_EVP_MD_CTX_free(ctx->mdctx);
  }
  free(ctx);
}

int _goboringcrypto_HMAC_Final(GO_HMAC_CTX *ctx,
			       unsigned char *md, unsigned int len)
{
  EVP_MD_CTX *mdctx = NULL;
  size_t slen = len;
  int ret = 0;

  mdctx = _goboringcrypto_EVP_MD_CTX_create();
  if (mdctx == NULL)
    goto err;

  if (_goboringcrypto_internal_EVP_MD_CTX_copy_ex(mdctx, ctx->mdctx) != 1)
    goto err;

  if (_goboringcrypto_EVP_DigestSignFinal(mdctx, md, &slen) != 1)
    goto err;

  ret = 1;

 err:
  _goboringcrypto_EVP_MD_CTX_free(mdctx);
  return ret;
}

#else

#include <openssl/hmac.h>

DEFINEFUNCINTERNAL(int, HMAC_Init_ex,
		   (HMAC_CTX *arg0, const void *arg1, int arg2, const EVP_MD *arg3, ENGINE *arg4),
		   (arg0, arg1, arg2, arg3, arg4))
DEFINEFUNCINTERNAL(int, HMAC_Update, (HMAC_CTX *arg0, const uint8_t *arg1, size_t arg2), (arg0, arg1, arg2))
DEFINEFUNCINTERNAL(int, HMAC_Final, (HMAC_CTX *arg0, uint8_t *arg1, unsigned int *arg2), (arg0, arg1, arg2))
DEFINEFUNCINTERNAL(size_t, HMAC_CTX_copy, (HMAC_CTX *dest, HMAC_CTX *src), (dest, src))
DEFINEFUNCINTERNAL(void, HMAC_CTX_cleanup, (HMAC_CTX *arg0), (arg0))
DEFINEFUNCINTERNAL(void, HMAC_CTX_init, (HMAC_CTX *arg0), (arg0))
DEFINEFUNCINTERNAL(const EVP_MD *, HMAC_CTX_get_md, (const HMAC_CTX *ctx), (ctx))
DEFINEFUNCINTERNAL(void, OPENSSL_cleanse, (void *ptr, size_t len), (ptr, len))

struct go_hmac_ctx {
  HMAC_CTX hctx;
  unsigned char *key;
  int keylen;
};

GO_HMAC_CTX *
_goboringcrypto_HMAC_CTX_new(const unsigned char *key, int keylen,
			     const EVP_MD *md)
{
  struct go_hmac_ctx *ctx;

  ctx = malloc(sizeof(*ctx));
  if (!ctx)
    return NULL;

  _goboringcrypto_internal_HMAC_CTX_init(&ctx->hctx);

  if (_goboringcrypto_internal_HMAC_Init_ex(&ctx->hctx, key, keylen, md, NULL) != 1)
    goto err;

  ctx->key = malloc(keylen);
  if (!ctx->key)
    goto err;
  memcpy(ctx->key, key, keylen);
  ctx->keylen = keylen;

  return ctx;

 err:
  _goboringcrypto_HMAC_CTX_free(ctx);
  return NULL;
}

int _goboringcrypto_HMAC_Update(GO_HMAC_CTX *ctx,
				const unsigned char *data, size_t len)
{
  return _goboringcrypto_internal_HMAC_Update(&ctx->hctx, data, len);
}

int _goboringcrypto_HMAC_CTX_reset(GO_HMAC_CTX *ctx)
{
  int ret;
  const EVP_MD *md = ctx->hctx.md;

  _goboringcrypto_internal_HMAC_CTX_init(&ctx->hctx);

  ret = _goboringcrypto_internal_HMAC_Init_ex(&ctx->hctx, ctx->key, ctx->keylen, md, NULL);
  if (ret != 1)
    return ret;

  return 1;
}

void _goboringcrypto_HMAC_CTX_free(GO_HMAC_CTX *ctx)
{
  _goboringcrypto_internal_HMAC_CTX_cleanup(&ctx->hctx);

  if (ctx->key) {
    _goboringcrypto_internal_OPENSSL_cleanse(ctx->key, ctx->keylen);
    free(ctx->key);
  }

  free(ctx);
}

int _goboringcrypto_HMAC_Final(GO_HMAC_CTX *ctx,
			       unsigned char *md, unsigned int len)
{
  HMAC_CTX hctx;
  int ret;

  ret = _goboringcrypto_internal_HMAC_CTX_copy(&hctx, &ctx->hctx);
  if (ret != 1)
    return ret;

  ret = _goboringcrypto_internal_HMAC_Final(&hctx, md, &len);
  _goboringcrypto_internal_HMAC_CTX_cleanup(&hctx);
  return ret;
}

#endif
