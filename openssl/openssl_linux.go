package openssl

// #include <dlfcn.h>
// #cgo LDFLAGS: -ldl
import "C"
import "errors"

func dlopen(version string) (unsafe.Pointer, error) {
	cv := C.CString("libcrypto.so." + version)
	defer C.free(unsafe.Pointer(cv))
	h := C.dlopen(cv, C.RTLD_LAZY|C.RTLD_LOCAL)
	if h == nil {
		errstr := C.GoString(C.dlerror())
		return nil, errors.New("openssl: can't load libcrypto.so." + version + ": " + errstr)
	}
	return h, nil
}
