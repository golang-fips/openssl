//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto/cipher"
	"errors"
)

// NewAESCipher creates and returns a new AES cipher.Block.
// The key argument should be the AES key, either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
// The returned cipher.Block implements the CBC, CTR, and/or GCM modes if
// the underlying OpenSSL library supports them.
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
	var block cipher.Block
	cbcSupportes := loadCipher(kind, cipherModeCBC) != nil
	ctrSupportes := loadCipher(kind, cipherModeCTR) != nil
	gcmSupportes := loadCipher(kind, cipherModeGCM) != nil
	aes := aesCipher{c}
	switch {
	case cbcSupportes && ctrSupportes && gcmSupportes:
		block = cipherWithCBC_CTR_GCM{aes,
			cipherWithCBC{aes},
			cipherWithCTR{aes},
			cipherWithGCM{aes},
		}
	case cbcSupportes && ctrSupportes && !gcmSupportes:
		block = cipherWithCBC_CTR{aes,
			cipherWithCBC{aes},
			cipherWithCTR{aes},
		}
	case cbcSupportes && !ctrSupportes && gcmSupportes:
		block = cipherWithCBC_GCM{aes,
			cipherWithCBC{aes},
			cipherWithGCM{aes},
		}
	case !cbcSupportes && ctrSupportes && gcmSupportes:
		block = cipherWithCTR_GCM{aes,
			cipherWithCTR{aes},
			cipherWithGCM{aes},
		}
	case cbcSupportes && !ctrSupportes && !gcmSupportes:
		block = cipherWithCBC{aes}
	case !cbcSupportes && ctrSupportes && !gcmSupportes:
		block = cipherWithCTR{aes}
	case !cbcSupportes && !ctrSupportes && gcmSupportes:
		block = cipherWithGCM{aes}
	case !cbcSupportes && !ctrSupportes && !gcmSupportes:
		block = aes
	default:
		panic("unreachable")
	}

	return block, nil
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	if c, ok := c.(interface {
		NewGCMTLS() (cipher.AEAD, error)
	}); ok {
		return c.NewGCMTLS()
	}
	return nil, errors.New("GCM not supported")
}

// NewGCMTLS13 returns a GCM cipher specific to TLS 1.3 and should not be used
// for non-TLS purposes.
func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) {
	if c, ok := c.(interface {
		NewGCMTLS13() (cipher.AEAD, error)
	}); ok {
		return c.NewGCMTLS13()
	}
	return nil, errors.New("GCM not supported")
}

// aesCipher implements the cipher.Block interface.
type aesCipher struct {
	cipher *evpCipher
}

func (c aesCipher) BlockSize() int {
	return c.cipher.blockSize
}

func (c aesCipher) Encrypt(dst, src []byte) {
	if err := c.cipher.encrypt(dst, src); err != nil {
		// crypto/aes expects that the panic message starts with "crypto/aes: ".
		panic("crypto/aes: " + err.Error())
	}
}

func (c aesCipher) Decrypt(dst, src []byte) {
	if err := c.cipher.decrypt(dst, src); err != nil {
		// crypto/aes expects that the panic message starts with "crypto/aes: ".
		panic("crypto/aes: " + err.Error())
	}
}

// cipherWithCBC implements the cipher.Block, aes.cbcEncAble and aes.cbcDecAble interfaces.
type cipherWithCBC struct {
	aesCipher
}

func (c cipherWithCBC) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return c.cipher.newCBC(iv, cipherOpEncrypt)
}

func (c cipherWithCBC) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return c.cipher.newCBC(iv, cipherOpDecrypt)
}

// cipherWithCTR implements the cipher.Block and aes.ctrAble interfaces.
type cipherWithCTR struct {
	aesCipher
}

func (c cipherWithCTR) NewCTR(iv []byte) cipher.Stream {
	return c.cipher.newCTR(iv)
}

// cipherWithGCM implements the cipher.Block and aes.gcmAble interface.
type cipherWithGCM struct {
	aesCipher
}

func (c cipherWithGCM) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	return c.cipher.newGCMChecked(nonceSize, tagSize)
}

func (c cipherWithGCM) NewGCMTLS() (cipher.AEAD, error) {
	return c.cipher.newGCM(cipherGCMTLS12)
}

func (c cipherWithGCM) NewGCMTLS13() (cipher.AEAD, error) {
	return c.cipher.newGCM(cipherGCMTLS13)
}

// cipherWithCBC_CTR implements the cipher.Block, aes.cbcEncAble, aes.cbcDecAble,
// and aes.ctrAble interfaces.
type cipherWithCBC_CTR struct {
	aesCipher
	cipherWithCBC
	cipherWithCTR
}

// cipherWithCBC_GCM implements the cipher.Block, aes.cbcEncAble, aes.cbcDecAble,
// and aes.gcmAble interfaces.
type cipherWithCBC_GCM struct {
	aesCipher
	cipherWithCBC
	cipherWithGCM
}

// cipherWithCTR_GCM implements the cipher.Block, aes.ctrAble, and aes.gcmAble interfaces.
type cipherWithCTR_GCM struct {
	aesCipher
	cipherWithCTR
	cipherWithGCM
}

// cipherWithCBC_CTR_GCM implements the cipher.Block, aes.cbcEncAble, aes.cbcDecAble,
// aes.ctrAble, and aes.gcmAble interfaces.
type cipherWithCBC_CTR_GCM struct {
	aesCipher
	cipherWithCBC
	cipherWithCTR
	cipherWithGCM
}

// The following interfaces have been copied out of crypto/aes/modes.go.

// gcmAble is implemented by cipher.Blocks that can provide an optimized
// implementation of GCM through the AEAD interface.
// See crypto/cipher/gcm.go.
type gcmAble interface {
	NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
}

// cbcEncAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CBC encryption through the cipher.BlockMode interface.
// See crypto/cipher/cbc.go.
type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) cipher.BlockMode
}

// cbcDecAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CBC decryption through the cipher.BlockMode interface.
// See crypto/cipher/cbc.go.
type cbcDecAble interface {
	NewCBCDecrypter(iv []byte) cipher.BlockMode
}

// ctrAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CTR through the cipher.Stream interface.
// See crypto/cipher/ctr.go.
type ctrAble interface {
	NewCTR(iv []byte) cipher.Stream
}

// Test that the interfaces are implemented.

var (
	_ cipher.Block = (*aesCipher)(nil)

	_ cipher.Block = (*cipherWithCBC)(nil)
	_ cbcEncAble   = (*cipherWithCBC)(nil)
	_ cbcDecAble   = (*cipherWithCBC)(nil)

	_ cipher.Block = (*cipherWithCTR)(nil)
	_ ctrAble      = (*cipherWithCTR)(nil)

	_ cipher.Block = (*cipherWithGCM)(nil)
	_ gcmAble      = (*cipherWithGCM)(nil)

	_ cipher.Block = (*cipherWithCBC_CTR)(nil)
	_ cbcEncAble   = (*cipherWithCBC_CTR)(nil)
	_ cbcDecAble   = (*cipherWithCBC_CTR)(nil)
	_ ctrAble      = (*cipherWithCBC_CTR)(nil)

	_ cipher.Block = (*cipherWithCBC_GCM)(nil)
	_ cbcEncAble   = (*cipherWithCBC_GCM)(nil)
	_ cbcDecAble   = (*cipherWithCBC_GCM)(nil)
	_ gcmAble      = (*cipherWithCBC_GCM)(nil)

	_ cipher.Block = (*cipherWithCTR_GCM)(nil)
	_ ctrAble      = (*cipherWithCTR_GCM)(nil)
	_ gcmAble      = (*cipherWithCTR_GCM)(nil)

	_ cipher.Block = (*cipherWithCBC_CTR_GCM)(nil)
	_ cbcEncAble   = (*cipherWithCBC_CTR_GCM)(nil)
	_ cbcDecAble   = (*cipherWithCBC_CTR_GCM)(nil)
	_ ctrAble      = (*cipherWithCBC_CTR_GCM)(nil)
	_ gcmAble      = (*cipherWithCBC_CTR_GCM)(nil)
)
