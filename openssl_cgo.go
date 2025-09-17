//go:build cgo

package openssl

/*
#include <stdlib.h> // for free()

static inline void
go_openssl_do_leak_check(void)
{
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if (defined(__SANITIZE_ADDRESS__) && __SANITIZE_ADDRESS__) ||	\
    __has_feature(address_sanitizer)
    extern void __lsan_do_leak_check(void);
    __lsan_do_leak_check();
#endif
}
*/
import "C"
import (
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	return C.GoString((*C.char)(unsafe.Pointer(ossl.OpenSSL_version(0))))
}

// goString converts a C string pointer to a Go string for cgo mode
func goString(ptr *byte) string {
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}

// goBytes converts a C byte array to a Go byte slice for cgo mode
func goBytes(ptr unsafe.Pointer, length int) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(ptr), length)
}

// isProviderAvailable checks if the provider with the given name is available.
// This function is used in export_test.go, but must be defined here as test files can't access C functions.
func isProviderAvailable(name string) bool {
	if vMajor == 1 {
		return false
	}
	providerName := C.CString(name)
	defer C.free(unsafe.Pointer(providerName))
	return ossl.OSSL_PROVIDER_available(nil, (*byte)(unsafe.Pointer(providerName))) == 1
}

func CheckLeaks() {
	C.go_openssl_do_leak_check()
}
