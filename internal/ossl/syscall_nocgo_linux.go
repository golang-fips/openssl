//go:build !cgo && linux

package ossl

import "syscall"

//go:cgo_import_dynamic _ _ "libdl.so.2"

// TODO implement syscallN for Linux nocgo
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	panic("Syscall not implemented on Linux")
}
