//go:build unix || windows

#include "shims.h"

#ifdef _WIN32
# include <windows.h>
# define dlsym (void*)GetProcAddress
#else
# include <dlfcn.h> // dlsym
#endif
#include <stdio.h> // fprintf

// go_openssl_fips_enabled returns 1 if FIPS mode is enabled, 0 otherwise.
// As a special case, it returns -1 if it cannot determine if FIPS mode is enabled.
// See openssl.FIPS for details about its implementation.
//
// This function is reimplemented here because openssl.FIPS assumes that
// all the OpenSSL bindings are loaded, that is, go_openssl_load_functions has
// already been called. On the other hand, go_openssl_fips_enabled is called from
// openssl.CheckVersion, which is used to check if a given OpenSSL shared library
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
    _EVP_MD_PTR (*EVP_MD_fetch)(void*, const char*, const char*) = (_EVP_MD_PTR (*)(void*, const char*, const char*))dlsym(handle, "EVP_MD_fetch");
    void (*EVP_MD_free)(_EVP_MD_PTR) = (void (*)(_EVP_MD_PTR))dlsym(handle, "EVP_MD_free");

    if (EVP_default_properties_is_fips_enabled == NULL || EVP_MD_fetch == NULL || EVP_MD_free == NULL) {
        // Shouldn't happen, but if it does, we can't determine if FIPS mode is enabled.
        return -1;
    }

    if (EVP_default_properties_is_fips_enabled(NULL) != 1)
        return 0;

    _EVP_MD_PTR md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    if (md == NULL)
        return 0;

    EVP_MD_free(md);
    return 1;
}

static unsigned long
version_num(void* handle)
{
    unsigned long (*fn)(void);
    // OPENSSL_version_num is defined in OpenSSL 1.1.0 and 1.1.1.
    fn = (unsigned long (*)(void))dlsym(handle, "OpenSSL_version_num");
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
