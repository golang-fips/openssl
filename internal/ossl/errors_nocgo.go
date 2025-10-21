//go:build !cgo && goexperiment.ms_nocgo_opensslcrypto

package ossl

import (
	"bytes"
	"errors"
	"strings"
	"unsafe"
)

const ERR_NUM_MAX = 16

// errState represents the OpenSSL error state for nocgo version
type errState struct {
	hasError bool
	codes    [ERR_NUM_MAX]uint64
}

// retrieveErrorState retrieves errors from the OpenSSL error queue.
// It might run on the system stack, so it can't allocate Go memory
// nor grow the stack over the nosplit limit.
//
//go:nosplit
func retrieveErrorState(state *errState) {
	state.hasError = true
	libcArgs := libcCallInfo{
		fn: _mkcgo_ERR_get_error,
	}
	for i := range ERR_NUM_MAX {
		syscallNAsm(&libcArgs)
		if libcArgs.r1 == 0 {
			break
		}
		state.codes[i] = uint64(libcArgs.r1)
	}
}

// newMkcgoErr creates a new error from the OpenSSL error queue for the nocgo version.
// The errst parameter is present for API compatibility with the CGO implementation,
// but is intentionally ignored in nocgo mode; errors are always retrieved directly from OpenSSL.
func newMkcgoErr(msg string, state *errState) error {
	if !state.hasError {
		return nil
	}
	if state.codes[0] == 0 {
		// If no errors in queue, return simple message
		return errors.New(msg + " failed")
	}

	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):")

	for _, code := range state.codes {
		if code == 0 {
			break
		}
		b.WriteByte('\n')
		var buf [256]byte
		ERR_error_string_n(code, unsafe.SliceData(buf[:]), len(buf))
		if termIdx := bytes.IndexByte(buf[:], 0); termIdx != -1 {
			b.Write(buf[:termIdx])
		} else {
			b.Write(buf[:])
		}
	}

	return errors.New(b.String())
}
