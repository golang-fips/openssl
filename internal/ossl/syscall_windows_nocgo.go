//go:build !cgo && windows

package ossl

import (
	"syscall"
)

//go:nosplit
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	r1, r2, err = syscall.SyscallN(fn, args...)
	return
}
