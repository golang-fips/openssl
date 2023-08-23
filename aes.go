//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto/cipher"
	"errors"
	"runtime"
)

const aesBlockSize = 16

type extraModes interface {
	// Copied out of crypto/aes/modes.go.
	NewCBCEncrypter(iv []byte) cipher.BlockMode
	NewCBCDecrypter(iv []byte) cipher.BlockMode
	NewCTR(iv []byte) cipher.Stream
	NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)

	// Invented for BoringCrypto.
	NewGCMTLS() (cipher.AEAD, error)
}

var _ extraModes = (*aesCipher)(nil)

func NewAESCipher(key []byte) (cipher.Block, error) {
	c := &evpCipher{key: make([]byte, len(key))}
	copy(c.key, key)

	switch len(c.key) * 8 {
	case 128:
		c.kind = cipherAES128
	case 192:
		c.kind = cipherAES192
	case 256:
		c.kind = cipherAES256
	default:
		return nil, errors.New("crypto/aes: invalid key size")
	}

	runtime.SetFinalizer(c, (*evpCipher).finalize)

	return &aesCipher{c}, nil
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return c.(*aesCipher).NewGCMTLS()
}

type aesCipher struct {
	*evpCipher
}

func (c *aesCipher) BlockSize() int { return aesBlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	c.encrypt(dst, src)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	c.decrypt(dst, src)
}

func (c *aesCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, true)
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, false)
}

func (c *aesCipher) NewCTR(iv []byte) cipher.Stream {
	return c.newCTR(iv)
}

func (c *aesCipher) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	return c.newGCMChecked(nonceSize, tagSize)
}

func (c *aesCipher) NewGCMTLS() (cipher.AEAD, error) {
	return c.newGCM(true)
}
