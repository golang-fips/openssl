//go:build unix || windows

#include "goopenssl.h"

#ifdef _WIN32
# include <windows.h>
# define dlsym (void*)GetProcAddress
#else
# include <dlfcn.h> // dlsym
#endif
#include <stdio.h> // fprintf

// Approach taken from .Net System.Security.Cryptography.Native
// https://github.com/dotnet/runtime/blob/f64246ce08fb7a58221b2b7c8e68f69c02522b0d/src/libraries/Native/Unix/System.Security.Cryptography.Native/opensslshim.c

#define DEFINEFUNC(ret, func, args, argscall)                  ret (*_g_##func)args;
#define DEFINEFUNC_LEGACY_1_1(ret, func, args, argscall)       DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)       DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)         DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall)              DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1_1(ret, func, args, argscall)            DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall)              DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall) DEFINEFUNC(ret, func, args, argscall)

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

// go_openssl_fips_enabled returns 1 if FIPS mode is enabled, 0 otherwise.
// See openssl.FIPS for details about its implementation.
//
// This function is reimplemented here because openssl.FIPS assumes that
// all the OpenSSL bindings are loaded, that is, go_openssl_load_functions has
// already been called. On the other hand, go_openssl_fips_enabled is called from
// openssl.CheckFIPS, which is used to check if a given OpenSSL shared library
// exists and is FIPS compliant. That shared library might not be the one that
// was passed to go_openssl_load_functions, or it might not even have been called at all.
//
// It is written in C because it is not possible to directly call C function pointers
// retrieved using dlsym from Go.
int
go_openssl_fips_enabled(void* handle)
{
    // For OpenSSL 1.x.
    int (*FIPS_mode)(void);
    FIPS_mode = (int (*)(void))dlsym(handle, "FIPS_mode");
    if (FIPS_mode != NULL)
        return FIPS_mode();

    // For OpenSSL 3.x.
    int (*EVP_default_properties_is_fips_enabled)(void*) = (int (*)(void*))dlsym(handle, "EVP_default_properties_is_fips_enabled");
    void *(*EVP_MD_fetch)(void*, const char*, const char*) = (void* (*)(void*, const char*, const char*))dlsym(handle, "EVP_MD_fetch");
    void (*EVP_MD_free)(void*) = (void (*)(void*))dlsym(handle, "EVP_MD_free");

    if (EVP_default_properties_is_fips_enabled == NULL || EVP_MD_fetch == NULL || EVP_MD_free == NULL) {
        // Shouldn't happen, but if it does, we can't determine if FIPS mode is enabled.
        return 0;
    }

    if (EVP_default_properties_is_fips_enabled(NULL) != 1)
        return 0;

    void *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    if (md == NULL)
        return 0;

    EVP_MD_free(md);
    return 1;
}

// Load all the functions stored in FOR_ALL_OPENSSL_FUNCTIONS
// and assign them to their corresponding function pointer
// defined in goopenssl.h.
void
go_openssl_load_functions(void* handle, unsigned int major, unsigned int minor, unsigned int patch)
{
#define DEFINEFUNC_INTERNAL(name, func)                                                                         \
    _g_##name = dlsym(handle, func);                                                                            \
    if (_g_##name == NULL) {                                                                                    \
        fprintf(stderr, "Cannot get required symbol " #func " from libcrypto version %u.%u\n", major, minor);   \
        abort();                                                                                                \
    }
#define DEFINEFUNC(ret, func, args, argscall) \
    DEFINEFUNC_INTERNAL(func, #func)
#define DEFINEFUNC_LEGACY_1_1(ret, func, args, argscall)  \
    if (major == 1 && minor == 1)                         \
    {                                                     \
        DEFINEFUNC_INTERNAL(func, #func)                  \
    }
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)  \
    if (major == 1 && minor == 0)                         \
    {                                                     \
        DEFINEFUNC_INTERNAL(func, #func)                  \
    }
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)  \
    if (major == 1)                                     \
    {                                                   \
        DEFINEFUNC_INTERNAL(func, #func)                \
    }
#define DEFINEFUNC_1_1(ret, func, args, argscall)     \
    if (major == 3 || (major == 1 && minor == 1))     \
    {                                                 \
        DEFINEFUNC_INTERNAL(func, #func)              \
    }
#define DEFINEFUNC_1_1_1(ret, func, args, argscall)     \
    if (major == 3 || (major == 1 && minor == 1 && patch == 1))     \
    {                                                 \
        DEFINEFUNC_INTERNAL(func, #func)              \
    }
#define DEFINEFUNC_3_0(ret, func, args, argscall)     \
    if (major == 3)                                   \
    {                                                 \
        DEFINEFUNC_INTERNAL(func, #func)              \
    }
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall)  \
    if (major == 1 && minor == 0)                                   \
    {                                                               \
        DEFINEFUNC_INTERNAL(func, #oldfunc)                         \
    }                                                               \
    else                                                            \
    {                                                               \
        DEFINEFUNC_INTERNAL(func, #func)                            \
    }
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall)  \
    if (major == 1)                                                 \
    {                                                               \
        DEFINEFUNC_INTERNAL(func, #oldfunc)                         \
    }                                                               \
    else                                                            \
    {                                                               \
        DEFINEFUNC_INTERNAL(func, #func)                            \
    }

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
}

static unsigned long
version_num(void* handle)
{
    unsigned long (*fn)(void);
    // OPENSSL_version_num is defined in OpenSSL 1.1.0 and 1.1.1.
    fn = (unsigned long (*)(void))dlsym(handle, "OpenSSL_version_num");
    if (fn != NULL)
        return fn();

    // SSLeay is defined in OpenSSL 1.0.2.
    fn = (unsigned long (*)(void))dlsym(handle, "SSLeay");
    if (fn != NULL)
        return fn();

    return 0;
} 

int
go_openssl_version_major(void* handle)
{
    unsigned int (*fn)(void);
    // OPENSSL_version_major is supported since OpenSSL 3.
    fn = (unsigned int (*)(void))dlsym(handle, "OPENSSL_version_major");
    if (fn != NULL)
        return (int)fn();

    // If OPENSSL_version_major is not defined, try with OpenSSL 1 functions.
    unsigned long num = version_num(handle);
    if (num < 0x10000000L || num >= 0x20000000L)
        return -1;

    return 1;
}

int
go_openssl_version_minor(void* handle)
{
    unsigned int (*fn)(void);
    // OPENSSL_version_minor is supported since OpenSSL 3.
    fn = (unsigned int (*)(void))dlsym(handle, "OPENSSL_version_minor");
    if (fn != NULL)
        return (int)fn();

    // If OPENSSL_version_minor is not defined, try with OpenSSL 1 functions.
    unsigned long num = version_num(handle);
    // OpenSSL version number follows this schema:
    // MNNFFPPS: major minor fix patch status.
    if (num < 0x10000000L || num >= 0x10200000L)
    {
        // We only support minor version 0 and 1,
        // so there is no need to implement an algorithm
        // that decodes the version number into individual components.
        return -1;
    }

    if (num >= 0x10100000L)
        return 1;
    
    return 0;
}

int
go_openssl_version_patch(void* handle)
{
    unsigned int (*fn)(void);
    // OPENSSL_version_patch is supported since OpenSSL 3.
    fn = (unsigned int (*)(void))dlsym(handle, "OPENSSL_version_patch");
    if (fn != NULL)
        return (int)fn();

    // If OPENSSL_version_patch is not defined, try with OpenSSL 1 functions.
    unsigned long num = version_num(handle);
    // OpenSSL version number follows this schema:
    // MNNFFPPS: major minor fix patch status.
    if (num < 0x10000000L || num >= 0x10200000L)
    {
        // We only support minor version 0 and 1,
        // so there is no need to implement an algorithm
        // that decodes the version number into individual components.
        return -1;
    }

    return (num >> 12) & 0xff;
}
