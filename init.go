//go:build !cmd_go_bootstrap

package openssl

import "C"
import (
	"errors"
	"unsafe"
)

// osslHandle is the handle to the OpenSSL shared library loaded in the [Init] function.
var osslHandle unsafe.Pointer

// opensslInit loads and initialize OpenSSL.
// If successful, it returns the major and minor OpenSSL version
// as reported by the OpenSSL API.
//
// See Init() for details about file.
func opensslInit(file string) error {
	// Load the OpenSSL shared library using dlopen.
	handle, err := openLibrary(file)
	if err != nil {
		return err
	}

	loadOpenSSLFuncs(handle)

	// Initialize OpenSSL.
	go_openssl_OPENSSL_init()
	if _, err = go_openssl_OPENSSL_init_crypto(
		_OPENSSL_INIT_ADD_ALL_CIPHERS|
			_OPENSSL_INIT_ADD_ALL_DIGESTS|
			_OPENSSL_INIT_LOAD_CONFIG|
			_OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
		nil); err != nil {
		dlclose(handle)
		return err
	}
	osslHandle = handle
	return nil
}

// loadFuncs loads and initialize the OpenSSL functions.
// See shims.go for the complete list of supported functions.
func loadOpenSSLFuncs(handle unsafe.Pointer) {
	mkcgoLoad_(handle)
	if vMajor == 1 {
		mkcgoLoad_legacy_1(handle)
		if vPatch == 1 {
			mkcgoLoad_111(handle)
		}
	} else {
		mkcgoLoad_111(handle)
		mkcgoLoad_3(handle)
	}
}

// initForCheckVersion loads and initialize only the
// functions required in [CheckVersion].
// It returns a function that must be called to release the resources.
// The function leaves all the global variables in the same state as they were
// before the call.
func initForCheckVersion(file string) (func(), error) {
	// This function can be called when the
	prevMajor, prevMinor, prevPatch := vMajor, vMinor, vPatch
	// Load the OpenSSL shared library using dlopen.
	handle, err := openLibrary(file)
	if err != nil {
		vMajor, vMinor, vPatch = prevMajor, prevMinor, prevPatch
		return nil, err
	}

	switch vMajor {
	case 1:
		mkcgoLoad_init_1(handle)
	case 3:
		mkcgoLoad_init_3(handle)
	default:
		// We shouldn't get here: openLibrary should have already returned an error.
		panic(errUnsupportedVersion())
	}
	return func() {
		dlclose(handle)
		// Undo all the changes made in this function.
		mkcgoUnload_version()
		mkcgoUnload_init_1()
		mkcgoUnload_init_3()
		vMajor, vMinor, vPatch = prevMajor, prevMinor, prevPatch
		if osslHandle != nil {
			loadOpenSSLFuncs(osslHandle)
		}
	}, nil
}

// openLibrary loads and initialize the version of OpenSSL.
func openLibrary(file string) (unsafe.Pointer, error) {
	handle, err := dlopen(file)
	if err != nil {
		return nil, err
	}
	if err := initVersion(handle); err != nil {
		return nil, err
	}
	return handle, nil
}

func initVersion(handle unsafe.Pointer) error {
	vMajor, vMinor, vPatch = 0, 0, 0
	// Retrieve the loaded OpenSSL version and check if it is supported.
	// Notice that major and minor could not match with the version parameter
	// in case the name of the shared library file differs from the OpenSSL
	// version it contains.
	mkcgoLoad_version(handle)
	if go_openssl_OPENSSL_version_major_Available() &&
		go_openssl_OPENSSL_version_minor_Available() &&
		go_openssl_OPENSSL_version_patch_Available() {
		// Likely OpenSSL 3 or later.
		vMajor = uint(go_openssl_OPENSSL_version_major())
		vMinor = uint(go_openssl_OPENSSL_version_minor())
		vPatch = uint(go_openssl_OPENSSL_version_patch())
	} else if go_openssl_OpenSSL_version_num_Available() {
		// Likely OpenSSL 1.
		ver := go_openssl_OpenSSL_version_num()
		vMajor = uint(ver >> 28)
		vMinor = uint(ver >> 20 & 0xFF)
		vPatch = uint(ver >> 12 & 0xFF)
	} else {
		return errors.New("openssl: version not available")
	}
	var supported bool
	if vMajor == 1 {
		supported = vMinor == 1
	} else if vMajor == 3 {
		// OpenSSL guarantees API and ABI compatibility within the same major version since OpenSSL 3.
		supported = true
	}
	if !supported {
		return errUnsupportedVersion()
	}
	return nil
}
