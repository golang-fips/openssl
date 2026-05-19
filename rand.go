//go:build !cmd_go_bootstrap

package openssl

import (
	"math"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

type randReader int

func (randReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	switch major() {
	case 1:
		if len(b) > math.MaxInt32 {
			// OpenSSL 1 does not support reading more than 2^31-1 bytes at once.
			// Instead of erroring out, read only up to 2^31-1 bytes and return
			// the number of bytes read.
			b = b[:math.MaxInt32]
		}
		if _, err := ossl.RAND_bytes(b); err != nil {
			return 0, err
		}
	default:
		if _, err := ossl.RAND_bytes_ex(nil, b, 0); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

const RandReader = randReader(0)
