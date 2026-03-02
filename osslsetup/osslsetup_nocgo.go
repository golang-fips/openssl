//go:build !cgo

package osslsetup

import "unsafe"

// goString converts a C string pointer to a Go string for nocgo mode
func goString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var result []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}
