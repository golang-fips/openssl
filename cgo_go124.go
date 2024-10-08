//go:build go1.24 && !cmd_go_bootstrap

package openssl

// #cgo noescape go_openssl_RAND_bytes
// #cgo nocallback go_openssl_RAND_bytes
import "C"
