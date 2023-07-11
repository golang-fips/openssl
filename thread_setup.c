//go:build linux
// +build linux

#include "goopenssl.h"
#include <pthread.h>
 
#define CRYPTO_LOCK 0x01

/* This array will store all of the mutexes available to OpenSSL. */ 
static pthread_mutex_t *mutex_buf = NULL;
 
static void locking_function(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&mutex_buf[n]);
    else
        pthread_mutex_unlock(&mutex_buf[n]);
}

static void thread_id(GO_CRYPTO_THREADID_PTR tid)
{
    go_openssl_CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

int go_openssl_thread_setup(void)
{
    mutex_buf = malloc(go_openssl_CRYPTO_num_locks()*sizeof(pthread_mutex_t));
    if (!mutex_buf)
        return 0;
    int i;
    for (i = 0; i < go_openssl_CRYPTO_num_locks(); i++)
        pthread_mutex_init(&mutex_buf[i], NULL);
    go_openssl_CRYPTO_THREADID_set_callback(thread_id);
    go_openssl_CRYPTO_set_locking_callback(locking_function);
    return 1;
}
