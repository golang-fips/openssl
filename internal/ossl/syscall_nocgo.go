//go:build !cgo

package ossl

import (
	"unsafe"
)

//go:linkname runtime_cgocall runtime.cgocall

//go:noescape
func runtime_cgocall(fn uintptr, arg unsafe.Pointer) int32 // from runtime/sys_libc.go

//go:linkname noescape
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

type libcCallInfo struct {
	fn      uintptr
	n       uintptr // number of parameters
	args    uintptr // parameters
	r1, r2  uintptr // return values
	errType uintptr
}

//go:noescape
func syscallNAsm(libcArgs *libcCallInfo)

// syscallNSystemStack performs a syscall on the system stack.
// It can't allocate Go memory nor grow the stack over the nosplit limit.
//
//go:nosplit
func syscallNSystemStack(libcArgs *libcCallInfo) {
	if libcArgs.errType != 0 {
		libcArgs.n--
	}
	syscallNAsm(libcArgs)
	if libcArgs.errType != 0 {
		_mkcgo_error_check(libcArgs.errType, libcArgs.r1, libcArgs.args, libcArgs.n)
	}
}

var syscallNSystemStack_trampoline byte
var syscallNSystemStackABIInternal = uintptr(unsafe.Pointer(&syscallNSystemStack_trampoline))

// syscallN performs a syscall with the given function and arguments.
//
// All its parameters and return values must be uintptr in order
// for the Go compiler to automatically set the //go:uintptrkeepalive
// directive (which we can't set manually here).
// See https://github.com/golang/go/blob/9a5a1202f4c4d5a7048b149b65c3e5b82a2de9aa/src/cmd/compile/internal/escape/call.go#L275.
//
//go:nosplit
func syscallN(errType uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	libcArgs := libcCallInfo{
		fn:      fn,
		n:       uintptr(len(args)),
		errType: errType,
	}
	if libcArgs.n != 0 {
		libcArgs.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	}
	runtime_cgocall(syscallNSystemStackABIInternal, unsafe.Pointer(&libcArgs))
	return libcArgs.r1, libcArgs.r2
}

// syscallNRaw performs a syscall with the given function and arguments,
// without any error checking nor switching to the system stack.
//
//go:nosplit
func syscallNRaw(fn uintptr, args ...uintptr) uintptr {
	libcArgs := libcCallInfo{
		fn: fn,
		n:  uintptr(len(args)),
	}
	if libcArgs.n != 0 {
		libcArgs.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	}
	syscallNAsm(&libcArgs)
	return libcArgs.r1
}
