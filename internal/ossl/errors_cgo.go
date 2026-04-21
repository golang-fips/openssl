package ossl

/*
#include "zossl.h"

// Force mkcgo_err_retrieve to be stack-guarded,
// even when it doesn't actually need it.
// This is necessary to ensure Go binaries built
// with -fstack-protector-strong comply with BinSkim BA3003,
// so that at least one function in the binary uses __stack_chk_guard.
// See https://github.com/microsoft/go/issues/2240.

#define MKCGO_STACK_PROTECT

#if defined(__has_attribute)
#if __has_attribute(stack_protect)
#undef MKCGO_STACK_PROTECT
#define MKCGO_STACK_PROTECT __attribute__((stack_protect))
#endif
#endif

// mkcgo_err_retrieve retrieves the error state from OpenSSL.
uintptr_t MKCGO_STACK_PROTECT mkcgo_err_retrieve() {
	// BIO operations using BIO_s_mem should not fail.
	_BIO_PTR bio = _mkcgo_BIO_new(_mkcgo_BIO_s_mem(), NULL);
	_mkcgo_ERR_print_errors(bio);
	return (uintptr_t)bio;
}
*/
import "C"
