//go:build !cmd_go_bootstrap

package openssl

// Go wrappers for testing the thread setup code as _test.go files cannot import "C".

// #include "thread_setup.h"
import "C"

// opensslThreadsCleanedUp returns the number of times the thread-local OpenSSL
// state has been cleaned up since the process started.
func opensslThreadsCleanedUp() uint {
	return uint(C.go_openssl_threads_cleaned_up)
}
