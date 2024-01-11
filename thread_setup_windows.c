//go:build windows

#include "goopenssl.h"
#include "thread_setup.h"

#include <stdlib.h>
#include <windows.h>

/* This array will store all of the mutexes available to OpenSSL. */
static HANDLE *mutex_buf = NULL;

static DWORD fls_index = FLS_OUT_OF_INDEXES;

/* Used by unit tests. */
volatile unsigned int go_openssl_threads_cleaned_up = 0;

static void locking_function(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        WaitForSingleObject(mutex_buf[n], INFINITE);
    else
        ReleaseMutex(mutex_buf[n]);
}

static void thread_id(GO_CRYPTO_THREADID_PTR tid)
{
    go_openssl_CRYPTO_THREADID_set_numeric(tid, (unsigned long)GetCurrentThreadId());

    // OpenSSL fetches the current thread ID whenever it does anything with the
    // per-thread error state, so this function is guaranteed to be executed at
    // least once on any thread with associated error state. As the Win32 API
    // reference documentation is unclear on whether the fiber-local storage
    // slot needs to be set to trigger the destructor on thread exit, set it to
    // a non-NULL value just in case.
    (void) FlsSetValue(fls_index, (void*)1);
    go_openssl_threads_cleaned_up++;
}

static void cleanup_thread_state(void *ignored)
{
    UNUSED(ignored);
    go_openssl_ERR_remove_thread_state(NULL);
}

int go_openssl_thread_setup(void)
{
    // Use the fiber-local storage API to hook a callback on thread exit.
    // https://devblogs.microsoft.com/oldnewthing/20191011-00/?p=102989
    fls_index = FlsAlloc(cleanup_thread_state);
    if (fls_index == FLS_OUT_OF_INDEXES)
        return 0;
    mutex_buf = malloc(go_openssl_CRYPTO_num_locks()*sizeof(HANDLE));
    if (!mutex_buf)
        return 0;
    int i;
    for (i = 0; i < go_openssl_CRYPTO_num_locks(); i++)
        mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
    go_openssl_CRYPTO_set_locking_callback(locking_function);
    // go_openssl_CRYPTO_set_id_callback is not strictly needed on Windows
    // as OpenSSL uses GetCurrentThreadId() by default.
    // But we need to piggyback off the callback for our own purposes.
    go_openssl_CRYPTO_THREADID_set_callback(thread_id);
    return 1;
}
