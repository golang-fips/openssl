//go:build !cmd_go_bootstrap && (cgo || goexperiment.ms_nocgo_opensslcrypto)

package osslsetup

import (
	"errors"
	"strconv"
	"sync"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

var (
	vMajor, vMinor, vPatch int
)

func VersionMajor() int {
	return vMajor
}

func VersionMinor() int {
	return vMinor
}

func VersionPatch() int {
	return vPatch
}

func utoa(n int) string {
	return strconv.FormatUint(uint64(n), 10)
}

func errUnsupportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + utoa(vMajor) + "." + utoa(vMinor) + "." + utoa(vPatch))
}

var (
	initOnce sync.Once
	initErr  error
)

// Init loads and initializes OpenSSL from the shared library at path.
// It must be called before any other OpenSSL call, except CheckVersion.
//
// Only the first call to Init is effective.
// Subsequent calls will return the same error result as the one from the first call.
//
// The file is passed to dlopen() verbatim to load the OpenSSL shared library.
// For example, `file=libcrypto.so.1.1.1k-fips` makes Init look for the shared
// library libcrypto.so.1.1.1k-fips.
func Init(file string) error {
	initOnce.Do(func() {
		initErr = opensslInit(file)
	})
	return initErr
}

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	return goString(ossl.OpenSSL_version(0))
}

// CheckVersion checks if the OpenSSL version can be loaded
// and if the FIPS mode is enabled.
// This function can be called before Init.
// All OpenSSL functions used in here should be tagged with "init_1" or "init_3" in shims.h.
func CheckVersion(version string) (exists, fips bool) {
	close, err := initForCheckVersion(version)
	if err != nil {
		return false, false
	}
	defer close()
	return true, FIPS()
}
