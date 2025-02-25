//go:build go1.24 && !cmd_go_bootstrap

package openssl

// The following noescape and nocallback directives are used to prevent the Go
// compiler from allocating function parameters on the heap. See
// https://github.com/golang/go/blob/0733682e5ff4cd294f5eccb31cbe87a543147bc6/src/cmd/cgo/doc.go#L439-L461
//
// If possible, write a C wrapper function to optimize a call rather than using
// this feature so the optimization will work for all supported Go versions.
//
// This is just a performance optimization. Only add functions that have been
// observed to benefit from these directives, not every function that is merely
// expected to meet the noescape/nocallback criteria.

/*
#cgo noescape go_openssl_RAND_bytes
#cgo nocallback go_openssl_RAND_bytes
#cgo noescape go_openssl_EVP_EncryptUpdate
#cgo nocallback go_openssl_EVP_EncryptUpdate
#cgo noescape go_openssl_EVP_EncryptFinal_ex
#cgo nocallback go_openssl_EVP_EncryptFinal_ex
#cgo noescape go_openssl_EVP_DecryptFinal_ex
#cgo nocallback go_openssl_EVP_DecryptFinal_ex
#cgo noescape go_openssl_EVP_DecryptUpdate
#cgo nocallback go_openssl_EVP_DecryptUpdate
#cgo noescape go_openssl_EVP_CipherUpdate
#cgo nocallback go_openssl_EVP_CipherUpdate
#cgo noescape go_openssl_EVP_PKEY_derive
#cgo nocallback go_openssl_EVP_PKEY_derive
#cgo noescape go_openssl_EVP_PKEY_get_raw_public_key
#cgo nocallback go_openssl_EVP_PKEY_get_raw_public_key
#cgo noescape go_openssl_EVP_PKEY_get_raw_private_key
#cgo nocallback go_openssl_EVP_PKEY_get_raw_private_key
#cgo noescape go_openssl_EVP_DigestSign
#cgo nocallback go_openssl_EVP_DigestSign
*/
import "C"
