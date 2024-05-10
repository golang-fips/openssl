//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"runtime"
	"sync"
)

// SupportsRC4 returns true if NewRC4Cipher is supported.
func SupportsRC4() bool {
	// True for stock OpenSSL 1 w/o FIPS.
	// False for stock OpenSSL 3 unless the legacy provider is available.
	return (versionAtOrAbove(1, 1, 0) || !FIPS()) && loadCipher(cipherRC4, cipherModeNone) != nil
}

// A RC4Cipher is an instance of RC4 using a particular key.
type RC4Cipher struct {
	ctx     C.GO_EVP_CIPHER_CTX_PTR
	ctxLock sync.Mutex
}

// NewRC4Cipher creates and returns a new Cipher.
func NewRC4Cipher(key []byte) (*RC4Cipher, error) {
	ctx, err := newCipherCtx(cipherRC4, cipherModeNone, cipherOpEncrypt, key, nil)
	if err != nil {
		return nil, err
	}
	c := &RC4Cipher{ctx: ctx}
	runtime.SetFinalizer(c, (*RC4Cipher).finalize)
	return c, nil
}

func (c *RC4Cipher) finalize() {
	if c.ctx != nil {
		C.go_openssl_EVP_CIPHER_CTX_free(c.ctx)
	}
}

// Reset zeros the key data and makes the Cipher unusable.
func (c *RC4Cipher) Reset() {
	c.ctxLock.Lock()
	defer c.ctxLock.Unlock()
	if c.ctx != nil {
		C.go_openssl_EVP_CIPHER_CTX_free(c.ctx)
		c.ctx = nil
	}
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
// Dst and src must overlap entirely or not at all.
func (c *RC4Cipher) XORKeyStream(dst, src []byte) {
	if c.ctx == nil || len(src) == 0 {
		return
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("crypto/rc4: invalid buffer overlap")
	}
	// panic if len(dst) < len(src) with a runtime out of bound error,
	// which is what crypto/rc4 does.
	c.ctxLock.Lock()
	defer c.ctxLock.Unlock()
	_ = dst[len(src)-1]
	var outLen C.int
	if C.go_openssl_EVP_EncryptUpdate(c.ctx, base(dst), &outLen, base(src), C.int(len(src))) != 1 {
		panic("crypto/cipher: EncryptUpdate failed")
	}
	if int(outLen) != len(src) {
		panic("crypto/rc4: src not fully XORed")
	}
	runtime.KeepAlive(c)
}
