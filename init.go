//go:build !cmd_go_bootstrap && cgo

package openssl

import (
	"errors"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// opensslInit loads and initialize OpenSSL.
// If successful, it returns the major and minor OpenSSL version
// as reported by the OpenSSL API.
//
// See Init() for details about file.
func opensslInit(file string) (major, minor, patch uint, err error) {
	// Load the OpenSSL shared library using dlopen.
	handle, err := dlopen(file)
	if err != nil {
		return 0, 0, 0, err
	}

	// Retrieve the loaded OpenSSL version and check if it is supported.
	// Notice that major and minor could not match with the version parameter
	// in case the name of the shared library file differs from the OpenSSL
	// version it contains.
	imajor := ossl.Go_openssl_version_major(handle)
	iminor := ossl.Go_openssl_version_minor(handle)
	ipatch := ossl.Go_openssl_version_patch(handle)
	if imajor < 0 || iminor < 0 || ipatch < 0 {
		return 0, 0, 0, errors.New("openssl: can't retrieve OpenSSL version")
	}
	major, minor, patch = uint(imajor), uint(iminor), uint(ipatch)
	var supported bool
	if major == 1 {
		supported = minor == 0 || minor == 1
	} else if major == 3 {
		// OpenSSL guarantees API and ABI compatibility within the same major version since OpenSSL 3.
		supported = true
	}
	if !supported {
		return 0, 0, 0, errUnsupportedVersion()
	}

	ossl.LoadLcrypto(handle)

	// Initialize OpenSSL.
	ossl.OPENSSL_init()
	if major == 1 && minor == 0 {
		ossl.ThreadSetup()
		ossl.OPENSSL_add_all_algorithms_conf()
		ossl.ERR_load_crypto_strings()
	} else {
		flags := ossl.OPENSSL_INIT_ADD_ALL_CIPHERS | ossl.OPENSSL_INIT_ADD_ALL_DIGESTS | ossl.OPENSSL_INIT_LOAD_CONFIG | ossl.OPENSSL_INIT_LOAD_CRYPTO_STRINGS
		if err := ossl.OPENSSL_init_crypto(uint64(flags), nil); err != nil {
			return 0, 0, 0, err
		}
	}
	return major, minor, patch, nil
}
