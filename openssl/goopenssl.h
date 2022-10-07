// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t

#include "shims.h"

int go_openssl_version_major(void* handle);
int go_openssl_version_minor(void* handle);
int go_openssl_thread_setup(void);
void go_openssl_load_functions(void* handle, int major, int minor);

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