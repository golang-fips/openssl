//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
// #include <dlfcn.h>
import "C"
import (
	"errors"
	"unsafe"
)

// knownVersions is a list of supported and well-known libcrypto.so suffixes in decreasing version order.
//
// FreeBSD library version numbering does not directly align to the version of OpenSSL.
// Its preferred search order is 11 -> 111.
//
// Some distributions use 1.0.0 and others (such as Debian) 1.0.2 to refer to the same OpenSSL 1.0.2 version.
//
// Fedora derived distros use different naming for the version 1.0.x.
var knownVersions = [...]string{"3", "1.1", "11", "111", "1.0.2", "1.0.0", "10"}

// opensslInit loads and initialize OpenSSL.
// If succeed, it returns the major and minor OpenSSL version
// as reported by the OpenSSL API.
//
// See Init() for details about version.
func opensslInit(version string) (major int, minor int, err error) {
	// Load the OpenSSL shareed library using dlopen.
	handle, err := loadLibrary(version)
	if err != nil {
		return 0, 0, err
	}

	// Retrieve the loaded OpenSSL version and check if it is supported.
	// Notice that major and minor could not match with the version parameter
	// in case the name of the shared library file differs from the OpenSSL
	// version it contains.
	major = int(C.go_openssl_version_major(handle))
	minor = int(C.go_openssl_version_minor(handle))
	if major == -1 || minor == -1 {
		return 0, 0, errors.New("openssl: can't retrieve OpenSSL version")
	}
	var supported bool
	if major == 1 {
		supported = minor == 0 || minor == 1
	} else if major == 3 {
		// OpenSSL guarantees API and ABI compatibility within the same major version since OpenSSL 3.
		supported = true
	}
	if !supported {
		return 0, 0, errUnsuportedVersion()
	}

	// Load the OpenSSL functions.
	// See shims.go for the complete list of supported functions.
	C.go_openssl_load_functions(handle, C.int(major), C.int(minor))

	// Initialize OpenSSL.
	C.go_openssl_OPENSSL_init()
	if major == 1 && minor == 0 {
		if C.go_openssl_thread_setup() != 1 {
			return 0, 0, fail("openssl: thread setup")
		}
		C.go_openssl_OPENSSL_add_all_algorithms_conf()
		C.go_openssl_ERR_load_crypto_strings()
	} else {
		flags := C.uint64_t(C.GO_OPENSSL_INIT_ADD_ALL_CIPHERS | C.GO_OPENSSL_INIT_ADD_ALL_DIGESTS | C.GO_OPENSSL_INIT_LOAD_CONFIG | C.GO_OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
		if C.go_openssl_OPENSSL_init_crypto(flags, nil) != 1 {
			return 0, 0, fail("openssl: init crypto")
		}
	}
	return major, minor, nil
}

func dlopen(version string) unsafe.Pointer {
	cv := C.CString("libcrypto.so." + version)
	defer C.free(unsafe.Pointer(cv))
	return C.dlopen(cv, C.RTLD_LAZY|C.RTLD_LOCAL)
}

func loadLibrary(version string) (unsafe.Pointer, error) {
	if version != "" {
		// If version is specified try to load it or error out.
		handle := dlopen(version)
		if handle == nil {
			errstr := C.GoString(C.dlerror())
			return nil, errors.New("openssl: can't load libcrypto.so." + version + ": " + errstr)
		}
		return handle, nil
	}
	// If the version is not specified, try loading from the list
	// of well known versions.
	for _, v := range knownVersions {
		handle := dlopen(v)
		if handle == nil {
			continue
		}
		return handle, nil
	}
	return nil, errors.New("openssl: can't load libcrypto.so using any known version suffix")
}
