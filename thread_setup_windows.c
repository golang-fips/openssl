//go:build windows

#include "goopenssl.h"

#include <stdlib.h>
#include <windows.h>

#define CRYPTO_LOCK      0x01

/* This array will store all of the mutexes available to OpenSSL. */
static HANDLE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        WaitForSingleObject(mutex_buf[n], INFINITE);
    else
        ReleaseMutex(mutex_buf[n]);
}

int go_openssl_thread_setup(void)
{
    mutex_buf = malloc(go_openssl_CRYPTO_num_locks()*sizeof(HANDLE));
    if (!mutex_buf)
        return 0;
    int i;
    for (i = 0; i < go_openssl_CRYPTO_num_locks(); i++)
        mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
    go_openssl_CRYPTO_set_locking_callback(locking_function);
    // go_openssl_CRYPTO_set_id_callback is not needed on Windows
    // as OpenSSL uses GetCurrentThreadId() by default.
    return 1;
}
