//go:build !cmd_go_bootstrap

package openssl

import (
	"runtime"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// SupportsRC4 returns true if NewRC4Cipher is supported.
func SupportsRC4() bool {
	switch major() {
	case 1:
		// RC4 is not part of the OpenSSL 1.x FIPS module.
		return !FIPS() && loadCipher(cipherRC4, cipherModeNone) != nil
	default:
		// On OpenSSL 3+ availability is decided by the algorithm probe:
		// EVP_CIPHER_fetch returns nil unless the legacy provider is loaded.
		return loadCipher(cipherRC4, cipherModeNone) != nil
	}
}

// A RC4Cipher is an instance of RC4 using a particular key.
type RC4Cipher struct {
	ctx ossl.EVP_CIPHER_CTX_PTR
}

// NewRC4Cipher creates and returns a new Cipher.
func NewRC4Cipher(key []byte) (*RC4Cipher, error) {
	ctx, err := newCipherCtx(cipherRC4, cipherModeNone, cipherOpEncrypt, key, nil)
	if err != nil {
		return nil, err
	}
	c := &RC4Cipher{ctx}
	runtime.SetFinalizer(c, (*RC4Cipher).finalize)
	return c, nil
}

func (c *RC4Cipher) finalize() {
	if c.ctx != nil {
		ossl.EVP_CIPHER_CTX_free(c.ctx)
	}
}

// Reset zeros the key data and makes the Cipher unusable.
func (c *RC4Cipher) Reset() {
	if c.ctx != nil {
		ossl.EVP_CIPHER_CTX_free(c.ctx)
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
	_ = dst[len(src)-1]
	var outLen int32
	if _, err := ossl.EVP_EncryptUpdate(c.ctx, dst, &outLen, src); err != nil {
		panic("crypto/rc4: " + err.Error())
	}
	if int(outLen) != len(src) {
		panic("crypto/rc4: src not fully XORed")
	}
	runtime.KeepAlive(c)
}
