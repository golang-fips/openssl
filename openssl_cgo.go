//go:build !cmd_go_bootstrap

package openssl

import "C"
import "unsafe"

// goString converts a C string pointer to a Go string for cgo mode
func goString(ptr *byte) string {
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}

// goBytes converts a C byte array to a Go byte slice for cgo mode
func goBytes(ptr unsafe.Pointer, length int) []byte {
	return C.GoBytes(ptr, C.int(length))
}
