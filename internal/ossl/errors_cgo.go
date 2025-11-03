package ossl

/*
#include "zossl.h"

// mkcgo_err_retrieve retrieves the error state from OpenSSL.
uintptr_t mkcgo_err_retrieve() {
	// BIO operations using BIO_s_mem should not fail.
	_BIO_PTR bio = _mkcgo_BIO_new(_mkcgo_BIO_s_mem(), NULL);
	_mkcgo_ERR_print_errors(bio);
	return (uintptr_t)bio;
}
*/
import "C"
