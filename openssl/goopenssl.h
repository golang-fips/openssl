// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t

#include "shims.h"

int go_openssl_version_major(void* handle);
int go_openssl_version_minor(void* handle);
int go_openssl_thread_setup(void);
void go_openssl_load_functions(void* handle, int major, int minor);
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
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)    \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)  \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall)   \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY_1_0
#undef DEFINEFUNC_LEGACY_1
#undef DEFINEFUNC_1_1
#undef DEFINEFUNC_3_0
#undef DEFINEFUNC_RENAMED_1_1
#undef DEFINEFUNC_RENAMED_3_0

// go_shaX is a SHA generic wrapper which hash p into out.
// One shot sha functions are expected to be fast, so
// we maximize performance by batching all cgo calls.
static inline int
go_shaX(GO_EVP_MD_PTR md, const void *p, size_t n, void *out)
{
    GO_EVP_MD_CTX_PTR ctx = go_openssl_EVP_MD_CTX_new();
    go_openssl_EVP_DigestInit_ex(ctx, md, NULL);
    int ret = go_openssl_EVP_DigestUpdate(ctx, p, n) &&
        go_openssl_EVP_DigestFinal_ex(ctx, out, NULL);
    go_openssl_EVP_MD_CTX_free(ctx);
    return ret;
}

// These wrappers allocate out_len on the C stack to avoid having to pass a pointer from Go, which would escape to the heap.
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


// These wrappers allocate out_len on the C stack, and check that it matches the expected
// value, to avoid having to pass a pointer from Go, which would escape to the heap.

static inline int
go_openssl_EVP_CIPHER_CTX_seal_wrapper(const GO_EVP_CIPHER_CTX_PTR ctx,
                                       unsigned char *out,
                                       const unsigned char *nonce,
                                       const unsigned char *in, int in_len,
                                       const unsigned char *aad, int aad_len)
{
    if (in_len == 0) in = "";
    if (aad_len == 0) aad = "";

    if (go_openssl_EVP_CipherInit_ex(ctx, NULL, NULL, NULL, nonce, GO_AES_ENCRYPT) != 1)
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
};

static inline int
go_openssl_EVP_CIPHER_CTX_open_wrapper(const GO_EVP_CIPHER_CTX_PTR ctx,
                                       unsigned char *out,
                                       const unsigned char *nonce,
                                       const unsigned char *in, int in_len,
                                       const unsigned char *aad, int aad_len,
                                       const unsigned char *tag)
{
    if (in_len == 0) in = "";
    if (aad_len == 0) aad = "";

    if (go_openssl_EVP_CipherInit_ex(ctx, NULL, NULL, NULL, nonce, GO_AES_DECRYPT) != 1)
        return 0;

    int discard_len, out_len;
    if (go_openssl_EVP_DecryptUpdate(ctx, NULL, &discard_len, aad, aad_len) != 1
        || go_openssl_EVP_DecryptUpdate(ctx, out, &out_len, in, in_len) != 1)
    {
        return 0;
    }

    if (go_openssl_EVP_CIPHER_CTX_ctrl(ctx, GO_EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *)(tag)) != 1)
        return 0;

    if (go_openssl_EVP_DecryptFinal_ex(ctx, out + out_len, &discard_len) != 1)
        return 0;

    if (out_len != in_len)
        return 0;

    return 1;
};

static inline void
go_openssl_params_free(OSSL_PARAM params[])
{
    if (params == NULL)
        return;

    // Loop through all the params until the first NULL key.
    for (; params->key != NULL; params++)
    {
        if (params->data != NULL)
        {
            free(params->data);
            params->data = NULL;
        }
    }
    return;
}
