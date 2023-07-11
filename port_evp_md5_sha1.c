//go:build linux

// The following is a partial backport of crypto/evp/m_md5_sha1.c,
// commit cbc8a839959418d8a2c2e3ec6bdf394852c9501e on the
// OpenSSL_1_1_0-stable branch.  The ctrl function has been removed.

/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "goopenssl.h"

#define NID_md5_sha1            114

#define MD5_CBLOCK      64
#define MD5_LBLOCK      (MD5_CBLOCK/4)
#define MD5_DIGEST_LENGTH 16
#define SHA_LBLOCK      16
#define SHA_DIGEST_LENGTH 20

#define EVP_PKEY_NULL_method    NULL,NULL,{0,0,0,0}

// Change: MD5_LONG and SHA_LONG have been expanded to unsigned int,
// which is always 32 bits. This avoids adding some obscure logic
// to support 16-bit platforms.

# define MD5_LONG unsigned int
# define SHA_LONG unsigned int

typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;

struct env_md_ctx_st {
    void *digest;
    void *engine;             
    unsigned long flags;
    void *md_data;
    void *pctx;
    void *update;
} /* EVP_MD_CTX */ ;

struct env_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    void *copy;
    void *cleanup;
    void *sign;
    void *verify;
    int required_pkey_type[5];
    int block_size;
    int ctx_size;
    void *md_ctrl;
} /* EVP_MD */ ;

typedef struct MD5state_st {
    MD5_LONG A, B, C, D;
    MD5_LONG Nl, Nh;
    MD5_LONG data[MD5_LBLOCK];
    MD5_LONG num;
} MD5_CTX;

typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    SHA_LONG num;
} SHA_CTX;

struct md5_sha1_ctx {
    MD5_CTX md5;
    SHA_CTX sha1;
};

static int md5_sha1_init(EVP_MD_CTX *ctx) {
    struct md5_sha1_ctx *mctx = ctx->md_data;
    if (!go_openssl_MD5_Init(&mctx->md5))
        return 0;
    return go_openssl_SHA1_Init(&mctx->sha1);
}

static int md5_sha1_update(EVP_MD_CTX *ctx, const void *data,
                                           size_t count) {
    struct md5_sha1_ctx *mctx = ctx->md_data;
    if (!go_openssl_MD5_Update(&mctx->md5, data, count))
        return 0;
    return go_openssl_SHA1_Update(&mctx->sha1, data, count);
}

static int md5_sha1_final(EVP_MD_CTX *ctx, unsigned char *md) {
    struct md5_sha1_ctx *mctx = ctx->md_data;
    if (!go_openssl_MD5_Final(md, &mctx->md5))
        return 0;
    return go_openssl_SHA1_Final(md + MD5_DIGEST_LENGTH, &mctx->sha1);
}

// Change: Removed:
// static int ctrl(EVP_MD_CTX *ctx, int cmd, int mslen, void *ms)

static const EVP_MD md5_sha1_md = {
    NID_md5_sha1,
    NID_md5_sha1,
    MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
    0,
    md5_sha1_init,
    md5_sha1_update,
    md5_sha1_final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method, // Change: inserted
    MD5_CBLOCK,
    sizeof(EVP_MD *) + sizeof(struct md5_sha1_ctx),
    NULL, // Change: was ctrl
};

// Change: Apply name mangling.
const GO_EVP_MD_PTR go_openssl_EVP_md5_sha1_backport(void) {
    return (const GO_EVP_MD_PTR)&md5_sha1_md;
}
