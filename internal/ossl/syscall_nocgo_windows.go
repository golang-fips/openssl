//go:build !cgo && windows

package ossl

import (
	"syscall"
	"unsafe"
)

var modkernel32 = syscall.NewLazyDLL("kernel32.dll")
var procGetProcAddress = modkernel32.NewProc("GetProcAddress")

func dlsym(handle unsafe.Pointer, symbol string, optional bool) uintptr {
	r0, _, err := syscall.SyscallN(procGetProcAddress.Addr(), uintptr(handle), uintptr(unsafe.Pointer(unsafe.StringData(symbol))))
	if err != 0 {
		if !optional {
			panic("cannot get required symbol " + symbol + ": " + err.Error())
		}
		return 0
	}
	return r0
}
