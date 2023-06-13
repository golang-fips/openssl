// go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
//  +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

#include "goopenssl.h"

#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define _GNU_SOURCE
#include <unistd.h>

#define CRYPTO_LOCK 0x01

/* This array will store all of the mutexes available to OpenSSL. */
static pthread_mutex_t *mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long id_function(void) {
  return (unsigned long)syscall(__NR_gettid);
}

int go_openssl_thread_setup(void) {
  mutex_buf = malloc(go_openssl_CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  if (!mutex_buf)
    return 0;
  int i;
  for (i = 0; i < go_openssl_CRYPTO_num_locks(); i++)
    pthread_mutex_init(&mutex_buf[i], NULL);
  go_openssl_CRYPTO_set_id_callback(id_function);
  go_openssl_CRYPTO_set_locking_callback(locking_function);
  return 1;
}
