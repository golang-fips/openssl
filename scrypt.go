//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"unsafe"
)

func Scrypt(password string, salt []byte, N, r, p, maxMem, keyLen uint64) ([]byte, error) {
	cpassword := C.CString(password)
	defer C.free((unsafe.Pointer)(cpassword))

	csalt := C.CBytes(salt)
	defer C.free((unsafe.Pointer)(csalt))

	key := make([]byte, keylen)

	res := C.go_openssl_EVP_PBE_scrypt(
		base(unsafe.StringData(password)),
		C.size_t(len(password)),
		base(salt),
		C.size_t(len(salt)),
		C.uint64_t(N),
		C.uint64_t(r),
		C.uint64_t(p),
		C.uint64_t(maxmem),
		(*C.uchar)(key),
		C.size_t(keylen),
	)
	if res != 1 {
		return nil, newOpenSSLError("EVP_PBE_scrypt")
	}
	return C.GoBytes(key, C.int(keylen)), nil
}
