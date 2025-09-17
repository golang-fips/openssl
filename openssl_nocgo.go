//go:build !cgo

package openssl

import (
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// goString converts a C string pointer to a Go string for nocgo mode
func goString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var result []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}

// goBytes converts a C byte array to a Go byte slice for nocgo mode
func goBytes(ptr unsafe.Pointer, length int) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(ptr), length)
}

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	// For nocgo, we need to convert the C string manually
	ptr := ossl.OpenSSL_version(0)
	return goString(ptr)
}

// isProviderAvailable reports whether a provider with the given name is available.
// This function is used in export_test.go, but must be defined here as test files can't access C functions.
func isProviderAvailable(name string) bool {
	if vMajor == 1 {
		return false
	}
	// Convert Go string to null-terminated byte slice for nocgo
	providerName := append([]byte(name), 0)
	return ossl.OSSL_PROVIDER_available(nil, &providerName[0]) == 1
}

func CheckLeaks() {
	// No-op for nocgo mode - leak checking requires CGO
}
