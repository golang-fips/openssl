//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto/cipher"
	"errors"
)

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
	var kind cipherKind
	switch len(key) * 8 {
	case 128:
		kind = cipherAES128
	case 192:
		kind = cipherAES192
	case 256:
		kind = cipherAES256
	default:
		return nil, errors.New("crypto/aes: invalid key size")
	}
	c, err := newEVPCipher(key, kind)
	if err != nil {
		return nil, err
	}
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

func (c *aesCipher) BlockSize() int {
	return c.blockSize
}

func (c *aesCipher) Encrypt(dst, src []byte) {
	c.encrypt(dst, src)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	c.decrypt(dst, src)
}

func (c *aesCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, cipherOpEncrypt)
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, cipherOpDecrypt)
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
