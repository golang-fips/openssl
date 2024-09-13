//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import "unsafe"

type RandReader struct{}

func (RandReader) Read(b []byte) (int, error) {
	// Note: RAND_bytes should never fail; the return value exists only for historical reasons.
	// We check it even so.
	if len(b) > 0 && C.go_openssl_RAND_bytes((*C.uchar)(unsafe.Pointer(&b[0])), C.int(len(b))) == 0 {
		return 0, newOpenSSLError("RAND_bytes")
	}
	return len(b), nil
}

func NewRandReader() RandReader {
	return RandReader{}
}
