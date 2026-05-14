//go:build !cmd_go_bootstrap

package osslsetup

import (
	"errors"
	"strconv"
	"sync"
	"syscall"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

var (
	vMajor, vMinor, vPatch int
)

// testedMajors lists the OpenSSL major versions this backend has been
// tested against. [openLibrary] rejects majors not in this list unless
// GODEBUG=ms_opensslallowuntested=1 is set. OpenSSL 1 is supported only
// at 1.1.1+; that minor/patch constraint is enforced separately in
// [openLibrary].
var testedMajors = [...]int{1, 3, 4}

// allowUntestedMajor reports whether the user has set
// GODEBUG=ms_opensslallowuntested=1. The "ms_" prefix marks this as a
// Microsoft-defined GODEBUG so it will not collide with upstream Go.
var allowUntestedMajor = sync.OnceValue(func() bool {
	godebug, _ := syscall.Getenv("GODEBUG")
	return godebugAllowUntested(godebug)
})

// godebugAllowUntested reports whether the comma-separated GODEBUG string
// contains ms_opensslallowuntested=1. Matches internal/godebug parsing:
// no whitespace trimming.
func godebugAllowUntested(godebug string) bool {
	const key = "ms_opensslallowuntested=1"
	var start int = 0
	for i := 0; i <= len(godebug); i++ {
		if i < len(godebug) && godebug[i] != ',' {
			continue
		}
		if godebug[start:i] == key {
			return true
		}
		start = i + 1
	}
	return false
}

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
	return errors.New("openssl: unsupported OpenSSL version: " + utoa(vMajor) + "." + utoa(vMinor) + "." + utoa(vPatch) + " (minimum supported version is 1.1.1)")
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
