// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t

#include "shims.h"


static inline void
go_openssl_do_leak_check(void)
{
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if (defined(__SANITIZE_ADDRESS__) && __SANITIZE_ADDRESS__) ||	\
    __has_feature(address_sanitizer)
    extern void __lsan_do_leak_check(void);
    __lsan_do_leak_check();
#endif
}

int go_openssl_fips_enabled(void* handle);
int go_openssl_version_major(void* handle);
int go_openssl_version_minor(void* handle);
int go_openssl_version_patch(void* handle);
int go_openssl_thread_setup(void);
void go_openssl_load_functions(void* handle, unsigned int major, unsigned int minor, unsigned int patch);
const GO_EVP_MD_PTR go_openssl_EVP_md5_sha1_backport(void);

// Define pointers to all the used OpenSSL functions.
// Calling C function pointers from Go is currently not supported.
// It is possible to circumvent this by using a C function wrapper.
// https://pkg.go.dev/cmd/cgo
#define DEFINEFUNC(ret, func, args, argscall)      \
    extern ret (*_g_##func)args;                   \
    static inline ret go_openssl_##func args       \
    {                                              \
        return _g_##func argscall;                 \
    }
#define DEFINEFUNC_LEGACY_1_1(ret, func, args, argscall)    \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)    \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)  \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall)   \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1_1(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY_1_1
#undef DEFINEFUNC_LEGACY_1_0
#undef DEFINEFUNC_LEGACY_1
#undef DEFINEFUNC_1_1
#undef DEFINEFUNC_1_1_1
#undef DEFINEFUNC_3_0
#undef DEFINEFUNC_RENAMED_1_1
#undef DEFINEFUNC_RENAMED_3_0

// go_hash_sum copies ctx into ctx2 and calls EVP_DigestFinal using ctx2.
// This is necessary because Go hash.Hash mandates that Sum has no effect
// on the underlying stream. In particular it is OK to Sum, then Write more,
// then Sum again, and the second Sum acts as if the first didn't happen.
// It is written in C because Sum() tend to be in the hot path,
// and doing one cgo call instead of two is a significant performance win.
static inline int
go_hash_sum(GO_EVP_MD_CTX_PTR ctx, GO_EVP_MD_CTX_PTR ctx2, unsigned char *out)
{
    if (go_openssl_EVP_MD_CTX_copy(ctx2, ctx) != 1)
        return 0;
    // TODO: use EVP_DigestFinal_ex once we know why it leaks
    // memory on OpenSSL 1.0.2.
    return go_openssl_EVP_DigestFinal(ctx2, out, NULL);
}

// These wrappers allocate length variables on the C stack to avoid having to pass a pointer from Go, which would escape to the heap.
// Use them only in situations where the output length can be safely discarded.

static inline int
go_openssl_EVP_EncryptUpdate_wrapper(GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, const unsigned char *in, int in_len)
{
    int len;
    return go_openssl_EVP_EncryptUpdate(ctx, out, &len, in, in_len);
}

static inline int
go_openssl_EVP_DecryptUpdate_wrapper(GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, const unsigned char *in, int in_len)
{
    int len;
    return go_openssl_EVP_DecryptUpdate(ctx, out, &len, in, in_len);
}

static inline int
go_openssl_EVP_CipherUpdate_wrapper(GO_EVP_CIPHER_CTX_PTR ctx, unsigned char *out, const unsigned char *in, int in_len)
{
    int len;
    return go_openssl_EVP_CipherUpdate(ctx, out, &len, in, in_len);
}

static inline int
go_openssl_EVP_PKEY_get_raw_public_key_wrapper(const GO_EVP_PKEY_PTR pkey, unsigned char *pub, size_t len)
{
    return go_openssl_EVP_PKEY_get_raw_public_key(pkey, pub, &len);
}

static inline int
go_openssl_EVP_PKEY_get_raw_private_key_wrapper(const GO_EVP_PKEY_PTR pkey, unsigned char *priv, size_t len)
{
    return go_openssl_EVP_PKEY_get_raw_private_key(pkey, priv, &len);
}

// These wrappers also allocate length variables on the C stack to avoid escape to the heap, but do return the result.
// A struct is returned that contains multiple return values instead of OpenSSL's approach of using pointers.

typedef struct
{
    int result;
    size_t keylen;
} go_openssl_EVP_PKEY_derive_wrapper_out;

static inline go_openssl_EVP_PKEY_derive_wrapper_out
go_openssl_EVP_PKEY_derive_wrapper(GO_EVP_PKEY_CTX_PTR ctx, unsigned char *key, size_t keylen)
{
    go_openssl_EVP_PKEY_derive_wrapper_out r = {0, keylen};
    r.result = go_openssl_EVP_PKEY_derive(ctx, key, &r.keylen);
    return r;
}

typedef struct
{
    int result;
    size_t siglen;
} go_openssl_EVP_DigestSign_wrapper_out;

static inline go_openssl_EVP_DigestSign_wrapper_out
go_openssl_EVP_DigestSign_wrapper(GO_EVP_MD_CTX_PTR ctx, unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    go_openssl_EVP_DigestSign_wrapper_out r = {0, siglen};
    r.result = go_openssl_EVP_DigestSign(ctx, sigret, &r.siglen, tbs, tbslen);
    return r;
}

// These wrappers allocate out_len on the C stack, and check that it matches the expected
// value, to avoid having to pass a pointer from Go, which would escape to the heap.

static inline int
go_openssl_EVP_CIPHER_CTX_seal_wrapper(const GO_EVP_CIPHER_CTX_PTR ctx,
                                       unsigned char *out,
                                       const unsigned char *nonce,
                                       const unsigned char *in, int in_len,
                                       const unsigned char *aad, int aad_len)
{
    if (in_len == 0) in = (const unsigned char *)"";
    if (aad_len == 0) aad = (const unsigned char *)"";

    if (go_openssl_EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce) != 1)
        return 0;

    int discard_len, out_len;
    if (go_openssl_EVP_EncryptUpdate(ctx, NULL, &discard_len, aad, aad_len) != 1
        || go_openssl_EVP_EncryptUpdate(ctx, out, &out_len, in, in_len) != 1
        || go_openssl_EVP_EncryptFinal_ex(ctx, out + out_len, &discard_len) != 1)
    {
        return 0;
    }

    if (in_len != out_len)
        return 0;

    return go_openssl_EVP_CIPHER_CTX_ctrl(ctx, GO_EVP_CTRL_GCM_GET_TAG, 16, out + out_len);
}

static inline int
go_openssl_EVP_CIPHER_CTX_open_wrapper(const GO_EVP_CIPHER_CTX_PTR ctx,
                                       unsigned char *out,
                                       const unsigned char *nonce,
                                       const unsigned char *in, int in_len,
                                       const unsigned char *aad, int aad_len,
                                       const unsigned char *tag)
{
    if (in_len == 0) {
        in = (const unsigned char *)"";
        // OpenSSL 1.0.2 in FIPS mode contains a bug: it will fail to verify
        // unless EVP_DecryptUpdate is called at least once with a non-NULL
        // output buffer.  OpenSSL will not dereference the output buffer when
        // the input length is zero, so set it to an arbitrary non-NULL pointer
        // to satisfy OpenSSL when the caller only has authenticated additional
        // data (AAD) to verify. While a stack-allocated buffer could be used,
        // that would risk a stack-corrupting buffer overflow if OpenSSL
        // unexpectedly dereferenced it. Instead pass a value which would
        // segfault if dereferenced on any modern platform where a NULL-pointer
        // dereference would also segfault.
        if (out == NULL) out = (unsigned char *)1;
    }
    if (aad_len == 0) aad = (const unsigned char *)"";

    if (go_openssl_EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce) != 1)
        return 0;

    // OpenSSL 1.0.x FIPS Object Module 2.0 versions below 2.0.5 require that
    // the tag be set before the ciphertext, otherwise EVP_DecryptUpdate returns
    // an error. At least one extant commercially-supported, FIPS validated
    // build of OpenSSL 1.0.2 uses FIPS module version 2.0.1. Set the tag first
    // to maximize compatibility with all OpenSSL version combinations.
    if (go_openssl_EVP_CIPHER_CTX_ctrl(ctx, GO_EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *)(tag)) != 1)
        return 0;

    int discard_len, out_len;
    if (go_openssl_EVP_DecryptUpdate(ctx, NULL, &discard_len, aad, aad_len) != 1
        || go_openssl_EVP_DecryptUpdate(ctx, out, &out_len, in, in_len) != 1)
    {
        return 0;
    }

    if (go_openssl_EVP_DecryptFinal_ex(ctx, out + out_len, &discard_len) != 1)
        return 0;

    if (out_len != in_len)
        return 0;

    return 1;
}

// Hand-roll custom wrappers for CRYPTO_malloc and CRYPTO_free which cast the
// function pointers to the correct signatures for OpenSSL 1.0.2.

static inline void *
go_openssl_CRYPTO_malloc_legacy102(int num, const char *file, int line) {
    return ((void *(*)(int, const char *, int))_g_CRYPTO_malloc)(num, file, line);
}

static inline void
go_openssl_CRYPTO_free_legacy102(void *str) {
    ((void (*)(void *))_g_CRYPTO_free)(str);
}