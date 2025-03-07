//go:build !cmd_go_bootstrap

package openssl

import "C"

type randReader int

func (randReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	// Note: RAND_bytes should never fail; the return value exists only for historical reasons.
	// We check it even so.
	if _, err := go_openssl_RAND_bytes(base(b), int32(len(b))); err != nil {
		return 0, err
	}
	return len(b), nil
}

const RandReader = randReader(0)
