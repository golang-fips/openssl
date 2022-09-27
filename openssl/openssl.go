//go:build linux && !android
// +build linux,!android

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

// #include "goopenssl.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"errors"
	"strconv"
	"sync"
)

var (
	// vMajor and vMinor hold the major/minor OpenSSL version.
	// It is only populated if Init has been called.
	vMajor, vMinor int
)

var (
	initOnce sync.Once
	initErr  error
)

// Init loads and initializes OpenSSL.
// It must be called before any other OpenSSL call.
//
// Only the first call to Init is effective,
// subsequent calls will return the same error result as the one from the first call.
//
// If version is not empty, its value will be appended to the OpenSSL shared library name
// as a version suffix when calling dlopen. For example, `version=1.1.1k-fips`
// makes Init look for the shared library libcrypto.so.1.1.1k-fips.
// If version is empty, Init will try to load the OpenSSL shared library
// using a list of supported and well-known version suffixes, going from higher to lower versions.
func Init(version string) error {
	initOnce.Do(func() {
		vMajor, vMinor, initErr = opensslInit(version)
	})
	return initErr
}

func errUnsupportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + strconv.Itoa(vMajor) + "." + strconv.Itoa(vMinor))
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	return C.GoString(C.go_openssl_OpenSSL_version(0))
}
