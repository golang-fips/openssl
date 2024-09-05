//go:build unix

#include "goopenssl.h"
#include "thread_setup.h"
#include <pthread.h>

/* This array will store all of the mutexes available to OpenSSL. */ 
static pthread_mutex_t *mutex_buf = NULL;

static pthread_key_t destructor_key;

/* Used by unit tests. */
volatile unsigned int go_openssl_threads_cleaned_up = 0;

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

    // OpenSSL fetches the current thread ID whenever it does anything with the
    // per-thread error state, so this function is guaranteed to be executed at
    // least once on any thread with associated error state. The thread-local
    // variable needs to be set to a non-NULL value so that the destructor will
    // be called when the thread exits.
    // The actual value does not matter, but should be a pointer with a valid size.
    // See https://github.com/golang-fips/openssl/pull/162
    static char stub;
    (void) pthread_setspecific(destructor_key, &stub);
}

static void cleanup_thread_state(void *ignored)
{
    UNUSED(ignored);
    go_openssl_ERR_remove_thread_state(NULL);
    // ERR_remove_thread_state(NULL) in turn calls our registered thread_id
    // callback via CRYPTO_THREADID_current(), which sets the thread-local
    // variable associated with this destructor to a non-NULL value. We have to
    // clear the variable ourselves to prevent pthreads from calling the
    // destructor again for the same thread.
    (void) pthread_setspecific(destructor_key, NULL);
    go_openssl_threads_cleaned_up++;
}

int go_openssl_thread_setup(void)
{
    if (pthread_key_create(&destructor_key, cleanup_thread_state) != 0)
        return 0;
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
