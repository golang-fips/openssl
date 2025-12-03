//go:build cgo || goexperiment.ms_nocgo_opensslcrypto

package ossl

import (
	"errors"
	"unsafe"
)

// newMkcgoErr constructs an error from the given message and OpenSSL error state.
func newMkcgoErr(msg string, state uintptr) error {
	if state == 0 {
		// No error
		return nil
	}
	bio := BIO_PTR(state)
	defer BIO_free(bio)
	// Retrieve pointer to data, which is owned by bio.
	var data *byte
	n := BIO_ctrl(bio, BIO_CTRL_INFO, 0, unsafe.Pointer(&data))
	if n == 0 {
		// If no errors in queue, return simple message
		return errors.New(msg + " failed")
	}
	const extra = "\nopenssl error(s):\n"
	buf := make([]byte, len(msg)+len(extra)+int(n))
	copy(buf, msg)
	copy(buf[len(msg):], extra)
	copy(buf[len(msg)+len(extra):], unsafe.Slice(data, n))
	// Remove trailing line jump if present.
	if buf[len(buf)-1] == '\n' {
		buf = buf[:len(buf)-1]
	}
	// Avoid an allocation by constructing the string directly from the byte slice.
	return errors.New(unsafe.String(unsafe.SliceData(buf), len(buf)))
}
