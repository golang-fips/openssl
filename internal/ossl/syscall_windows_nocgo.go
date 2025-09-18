//go:build windows && !cgo

package ossl

import (
	"syscall"
	"unsafe"
)

var modkernel32 = syscall.NewLazyDLL("kernel32.dll")
var procGetProcAddress = modkernel32.NewProc("GetProcAddress")

//go:nosplit
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	r1, r2, err = syscall.SyscallN(fn, args...)
	return
}

func Dlsym(handle unsafe.Pointer, symbol *byte) (unsafe.Pointer, error) {
	r0, _, err := syscall.SyscallN(procGetProcAddress.Addr(), uintptr(handle), uintptr(unsafe.Pointer(symbol)))
	if err != 0 {
		return nil, err
	}
	return unsafe.Pointer(r0), nil
}
