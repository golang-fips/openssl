//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"hash"
	"io"
	"runtime"
)

func SupportsHKDF() bool {
	return version1_1_1_or_above()
}

func newHKDF(h func() hash.Hash, mode int) (*hkdf, error) {
	if !SupportsHKDF() {
		return nil, errUnsupportedVersion()
	}

	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}
	ctx, err := newEvpPkeyCtxFromID(C.GO_EVP_PKEY_HKDF)
	if err != nil {
		return nil, err
	}
	if err := ctx.deriveInit(); err != nil {
		ctx.free()
		return nil, err
	}
	if err := ctx.setHKDFProps(mode, md, nil, nil, nil); err != nil {
		ctx.free()
		return nil, err
	}
	c := &hkdf{ctx: ctx, hashLen: ch.Size()}
	runtime.SetFinalizer(c, (*hkdf).finalize)
	return c, nil
}

type hkdf struct {
	ctx evpPkeyCtx

	hashLen int
	buf     []byte
}

func (c *hkdf) finalize() {
	c.ctx.free()
}

func (c *hkdf) Read(p []byte) (int, error) {
	defer runtime.KeepAlive(c)

	// EVP_PKEY_derive doesn't support incremental output, each call
	// derives the key from scratch and returns the requested bytes.
	// To implement io.Reader, we need to ask for len(c.buf) + len(p)
	// bytes and copy the last derived len(p) bytes to p.
	// We use c.buf to know how many bytes we've already derived and
	// to avoid allocating the whole output buffer on each call.
	prevLen := len(c.buf)
	needLen := len(p)
	remains := 255*c.hashLen - prevLen
	// Check whether enough data can be generated.
	if remains < needLen {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	c.buf = append(c.buf, make([]byte, needLen)...)
	var err error
	if c.buf, err = c.ctx.derive(c.buf); err != nil {
		return 0, err
	}
	n := copy(p, c.buf[prevLen:])
	return n, nil
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	c, err := newHKDF(h, C.GO_EVP_KDF_HKDF_MODE_EXTRACT_ONLY)
	if err != nil {
		return nil, err
	}
	if c.ctx.setHKDFProps(0, nil, secret, salt, nil) != nil {
		return nil, err
	}
	return c.ctx.derive(nil)
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	c, err := newHKDF(h, C.GO_EVP_KDF_HKDF_MODE_EXPAND_ONLY)
	if err != nil {
		return nil, err
	}
	if c.ctx.setHKDFProps(0, nil, pseudorandomKey, nil, info) != nil {
		return nil, err
	}
	return c, nil
}
