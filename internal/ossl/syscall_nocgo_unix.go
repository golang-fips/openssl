//go:build !cgo && unix

package ossl

import "unsafe"

func dlsym(handle unsafe.Pointer, symbol string, optional bool) unsafe.Pointer {
	r0 := Dlsym(handle, unsafe.StringData(symbol))
	if r0 == nil {
		if !optional {
			panic("cannot get required symbol " + symbol)
		}
		return nil
	}
	return unsafe.Pointer(r0)
}
