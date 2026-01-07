//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto/cipher"
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

const (
	chacha20Poly1305KeySize   = 32
	chacha20Poly1305NonceSize = 12
	chacha20Poly1305Overhead  = 16
)

var supportsChaCha20Poly1305 = sync.OnceValue(func() bool {
	return loadCipher(cipherChaCha20Poly1305, cipherModeNone) != nil
})

func SupportsChaCha20Poly1305() bool {
	return supportsChaCha20Poly1305()
}

type chacha20poly1305 struct {
	key [chacha20Poly1305KeySize]byte
}

// NewChaCha20Poly1305 returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20Poly1305KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(chacha20poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

func (c *chacha20poly1305) NonceSize() int {
	return chacha20Poly1305NonceSize
}

func (c *chacha20poly1305) Overhead() int {
	return chacha20Poly1305Overhead
}

func (c *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chacha20Poly1305NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Seal")
	}
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+chacha20Poly1305Overhead)
	if inexactOverlap(out, plaintext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if anyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	ctx, err := newCipherCtx(cipherChaCha20Poly1305, cipherModeNone, cipherOpEncrypt, c.key[:], nil)
	if err != nil {
		panic(err)
	}
	defer ossl.EVP_CIPHER_CTX_free(ctx)
	if _, err := ossl.EVP_CIPHER_CTX_ctrl(ctx, ossl.EVP_CTRL_AEAD_SET_IVLEN, int32(len(nonce)), nil); err != nil {
		panic(err)
	}
	if _, err := ossl.EVP_EncryptInit_ex(ctx, nil, nil, nil, base(nonce)); err != nil {
		panic(err)
	}
	if len(additionalData) > 0 {
		var discard int32
		if _, err := ossl.EVP_EncryptUpdate(ctx, nil, &discard, base(additionalData), int32(len(additionalData))); err != nil {
			panic(err)
		}
	}
	var outl int32
	if len(plaintext) > 0 {
		if _, err := ossl.EVP_EncryptUpdate(ctx, base(out), &outl, base(plaintext), int32(len(plaintext))); err != nil {
			panic(err)
		}
	}
	if _, err := ossl.EVP_EncryptFinal_ex(ctx, base(out[outl:]), &outl); err != nil {
		panic(err)
	}
	tag := out[len(out)-chacha20Poly1305Overhead:]
	if _, err := ossl.EVP_CIPHER_CTX_ctrl(ctx, ossl.EVP_CTRL_AEAD_GET_TAG, 16, unsafe.Pointer(base(tag))); err != nil {
		panic(err)
	}
	runtime.KeepAlive(c)
	return ret
}

func (c *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha20Poly1305NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}
	tag := ciphertext[len(ciphertext)-chacha20Poly1305Overhead:]
	ciphertext = ciphertext[:len(ciphertext)-chacha20Poly1305Overhead]
	ret, out := sliceForAppend(dst, len(ciphertext))
	if inexactOverlap(out, ciphertext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if anyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	ctx, err := newCipherCtx(cipherChaCha20Poly1305, cipherModeNone, cipherOpDecrypt, c.key[:], nil)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_CIPHER_CTX_free(ctx)
	if _, err := ossl.EVP_CIPHER_CTX_ctrl(ctx, ossl.EVP_CTRL_AEAD_SET_IVLEN, int32(len(nonce)), nil); err != nil {
		return nil, err
	}
	if _, err := ossl.EVP_CIPHER_CTX_ctrl(ctx, ossl.EVP_CTRL_AEAD_SET_TAG, 16, unsafe.Pointer(base(tag))); err != nil {
		return nil, err
	}
	if _, err := ossl.EVP_DecryptInit_ex(ctx, nil, nil, nil, base(nonce)); err != nil {
		return nil, err
	}
	if len(additionalData) > 0 {
		var discard int32
		if _, err := ossl.EVP_DecryptUpdate(ctx, nil, &discard, base(additionalData), int32(len(additionalData))); err != nil {
			return nil, err
		}
	}
	var outl int32
	if len(ciphertext) > 0 {
		if _, err := ossl.EVP_DecryptUpdate(ctx, base(out), &outl, base(ciphertext), int32(len(ciphertext))); err != nil {
			return nil, err
		}
	}
	if _, err := ossl.EVP_DecryptFinal_ex(ctx, base(out[outl:]), &outl); err != nil {
		return nil, errOpen
	}
	runtime.KeepAlive(c)
	return ret[:len(dst)+len(ciphertext)], nil
}
