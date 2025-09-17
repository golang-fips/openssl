//go:build unix && !cmd_go_bootstrap && !cgo

package openssl

import (
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// dlopen for nocgo mode - returns a dummy handle since libraries are already linked
func dlopen(file string) (handle unsafe.Pointer, err error) {
	handle, _ = ossl.Dlopen(unsafe.StringData(file+"\x00"), 1|4)
	if handle == nil {
		panic("Dlopen failed in nocgo mode")
	}
	return handle, nil
}

// dlclose for nocgo mode - no-op since we don't actually open anything
func dlclose(handle unsafe.Pointer) error {
	// No-op since we don't actually open libraries in nocgo mode
	return nil
}
