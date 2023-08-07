//go:build linux && !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import "unsafe"

type randReader int

func (randReader) Read(b []byte) (int, error) {
	// Note: RAND_bytes should never fail; the return value exists only for historical reasons.
	// We check it even so.
	if len(b) > 0 && C.go_openssl_RAND_bytes((*C.uchar)(unsafe.Pointer(&b[0])), C.int(len(b))) == 0 {
		return 0, newOpenSSLError("RAND_bytes")
	}
	return len(b), nil
}

const RandReader = randReader(0)
