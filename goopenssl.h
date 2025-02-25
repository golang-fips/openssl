// This header file describes the OpenSSL ABI as built for use in Go.

#include "shims.h"

// Suppress warnings about unused parameters.
#define UNUSED(x) (void)(x)

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
void go_openssl_load_functions(void* handle, unsigned int major, unsigned int minor, unsigned int patch);

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
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)  \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1_1(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_VARIADIC_3_0(ret, func, newname, args, argscall)     \
    DEFINEFUNC(ret, newname, args, argscall)

FOR_ALL_OPENSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY_1_1
#undef DEFINEFUNC_LEGACY_1
#undef DEFINEFUNC_1_1_1
#undef DEFINEFUNC_3_0
#undef DEFINEFUNC_RENAMED_3_0
#undef DEFINEFUNC_VARIADIC_3_0

// go_hash_sum copies ctx into ctx2 and calls EVP_DigestFinal_ex using ctx2.
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
    return go_openssl_EVP_DigestFinal_ex(ctx2, out, NULL);
}
