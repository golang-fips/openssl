//go:build linux && !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto/cipher"
	"errors"
)

// SupportsDESCipher returns true if NewDESCipher is supported.
func SupportsDESCipher() bool {
	// True for stock OpenSSL 1.
	// False for stock OpenSSL 3 unless the legacy provider is available.
	return loadCipher(cipherDES, cipherModeECB) != nil
}

// SupportsTripleDESCipher returns true if NewTripleDESCipher is supported.
func SupportsTripleDESCipher() bool {
	// Should always be true for stock OpenSSL,
	// even when using the FIPS provider.
	return loadCipher(cipherDES3, cipherModeECB) != nil
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 8 {
		return nil, errors.New("crypto/des: invalid key size")
	}
	c, err := newEVPCipher(key, cipherDES)
	if err != nil {
		return nil, err
	}
	return &desCipher{c}, nil
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 24 {
		return nil, errors.New("crypto/des: invalid key size")
	}
	c, err := newEVPCipher(key, cipherDES3)
	if err != nil {
		return nil, err
	}
	return &desCipher{c}, nil
}

type desExtraModes interface {
	NewCBCEncrypter(iv []byte) cipher.BlockMode
	NewCBCDecrypter(iv []byte) cipher.BlockMode
}

var _ desExtraModes = (*desCipher)(nil)

type desCipher struct {
	*evpCipher
}

func (c *desCipher) BlockSize() int {
	return c.blockSize
}

func (c *desCipher) Encrypt(dst, src []byte) {
	c.encrypt(dst, src)
}

func (c *desCipher) Decrypt(dst, src []byte) {
	c.decrypt(dst, src)
}

func (c *desCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, true)
}

func (c *desCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return c.newCBC(iv, false)
}
