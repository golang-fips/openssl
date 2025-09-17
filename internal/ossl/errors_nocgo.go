//go:build !cgo

package ossl

import (
	"errors"
)

// newMkcgoErr creates a new error from OpenSSL error queue for nocgo version
// This returns a simple error message since detailed error introspection
// requires more complex OpenSSL error queue handling
func newMkcgoErr(msg string) error {
	return errors.New(msg + " failed")
}

// checkOpenSSLResult checks an OpenSSL function result and returns an error if it failed
// This is used to provide proper error handling in nocgo mode
func checkOpenSSLResult(code int32, funcName string) error {
	if code <= 0 {
		return newMkcgoErr(funcName)
	}
	return nil
}
