//go:build go1.22 && !cmd_go_bootstrap

package openssl

/*
// The following noescape and nocallback directives are used to
// prevent the Go compiler from allocating function parameters on the
// heap. This is just a performance optimization. Only add those
// functions that are known to allocate.
#cgo noescape go_openssl_EVP_PKEY_derive
#cgo nocallback go_openssl_EVP_PKEY_derive
#cgo noescape go_openssl_EVP_EncryptUpdate
#cgo nocallback go_openssl_EVP_EncryptUpdate
*/
import "C"
