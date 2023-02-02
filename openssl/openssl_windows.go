package openssl

// #include <windows.h>
import "C"
import (
	"runtime"
	"syscall"
	"unsafe"
)

func dlopen(version string) (unsafe.Pointer, error) {
	name, err := syscall.UTF16PtrFromString("libcrypto" + version + ".dll")
	if err != nil {
		return nil, err
	}
	h := C.LoadLibraryExW((*C.ushort)(unsafe.Pointer(name)), nil, C.LOAD_LIBRARY_SEARCH_SYSTEM32)
	runtime.KeepAlive(name)
	if h == nil {
		code := C.GetLastError()
		return nil, syscall.Errno(code)
	}
	return unsafe.Pointer(h), nil
}
