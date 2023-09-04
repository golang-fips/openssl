//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
)

func SupportsTLS1PRF() bool {
	return vMajor > 1 ||
		(vMajor >= 1 && vMinor >= 1)
}

func TLS1PRF(secret, label, seed []byte, keyLen int, h func() hash.Hash) ([]byte, error) {
	var md C.GO_EVP_MD_PTR
	if h == nil {
		// TLS 1.0/1.1 PRF doesn't allow to specify the hash function,
		// it always uses MD5SHA1. If h is nil, then assume
		// that the caller wants to use TLS 1.0/1.1 PRF.
		// OpenSSL detects this case by checking if the hash
		// function is MD5SHA1.
		md = cryptoHashToMD(crypto.MD5SHA1)
	} else {
		md = hashToMD(h())
	}
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}

	ctx, err := newEvpPkeyCtxFromID(C.GO_EVP_PKEY_TLS1_PRF)
	if err != nil {
		return nil, err
	}
	defer ctx.free()

	if err := ctx.deriveInit(); err != nil {
		return nil, err
	}
	if err := ctx.setTLS1PRFProps(md, secret, label, seed); err != nil {
		return nil, err
	}
	out := make([]byte, keyLen)
	out, err = ctx.derive(out)
	if err != nil {
		return nil, err
	}
	if len(out) != keyLen {
		return nil, errors.New("tls1-prf: entropy limit reached")
	}
	return out, nil
}
