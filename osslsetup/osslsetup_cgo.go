//go:build !cmd_go_bootstrap

package osslsetup

import "C"
import "unsafe"

// goString converts a C string pointer to a Go string for cgo mode
func goString(ptr *byte) string {
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}
