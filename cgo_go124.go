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
#cgo noescape RAND_bytes
#cgo nocallback RAND_bytes
#cgo noescape EVP_EncryptUpdate
#cgo nocallback EVP_EncryptUpdate
#cgo noescape EVP_EncryptFinal_ex
#cgo nocallback EVP_EncryptFinal_ex
#cgo noescape EVP_DecryptFinal_ex
#cgo nocallback EVP_DecryptFinal_ex
#cgo noescape EVP_DecryptUpdate
#cgo nocallback EVP_DecryptUpdate
#cgo noescape EVP_CipherUpdate
#cgo nocallback EVP_CipherUpdate
#cgo noescape EVP_PKEY_derive
#cgo nocallback EVP_PKEY_derive
#cgo noescape EVP_PKEY_get_raw_public_key
#cgo nocallback EVP_PKEY_get_raw_public_key
#cgo noescape EVP_PKEY_get_raw_private_key
#cgo nocallback EVP_PKEY_get_raw_private_key
#cgo noescape EVP_DigestSign
#cgo nocallback EVP_DigestSign
#cgo noescape EVP_Digest
#cgo nocallback EVP_Digest
#cgo noescape EVP_DigestUpdate
#cgo nocallback EVP_DigestUpdate
*/
import "C"
