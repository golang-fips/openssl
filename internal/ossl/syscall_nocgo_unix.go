//go:build !cgo && unix && (go1.27 || !s390x)

package ossl

import (
	"unsafe"

	_ "github.com/golang-fips/openssl/v2/internal/fakecgo"
)

func dlsym(handle unsafe.Pointer, symbol string, optional bool) uintptr {
	r0 := Dlsym(handle, unsafe.StringData(symbol))
	if r0 == nil {
		if !optional {
			panic("cannot get required symbol " + symbol)
		}
		return 0
	}
	return uintptr(r0)
}
