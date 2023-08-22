//go:build linux && !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"runtime"
	"strconv"
	"sync"
	"unsafe"
)

type cipherKind int8

const (
	cipherAES128_ECB cipherKind = iota
	cipherAES192_ECB
	cipherAES256_ECB
	cipherAES128_CBC
	cipherAES192_CBC
	cipherAES256_CBC
	cipherAES128_CTR
	cipherAES192_CTR
	cipherAES256_CTR
	cipherAES128_GCM
	cipherAES192_GCM
	cipherAES256_GCM
)

// cacheCipher is a cache of cipherKind to GO_EVP_CIPHER_PTR.
var cacheCipher sync.Map

// newCipher returns a cipher object for the given k.
func newCipher(k cipherKind) (cipher C.GO_EVP_CIPHER_PTR) {
	if v, ok := cacheCipher.Load(k); ok {
		return v.(C.GO_EVP_CIPHER_PTR)
	}
	defer func() {
		if cipher != nil && vMajor == 3 {
			// On OpenSSL 3, directly operating on a EVP_CIPHER object
			// not created by EVP_CIPHER has negative performance
			// implications, as cipher operations will have
			// to fetch it on every call. Better to just fetch it once here.
			cipher = C.go_openssl_EVP_CIPHER_fetch(nil, C.go_openssl_EVP_CIPHER_get0_name(cipher), nil)
		}
		cacheCipher.Store(k, cipher)
	}()
	switch k {
	case cipherAES128_CBC:
		cipher = C.go_openssl_EVP_aes_128_cbc()
	case cipherAES192_CBC:
		cipher = C.go_openssl_EVP_aes_192_cbc()
	case cipherAES256_CBC:
		cipher = C.go_openssl_EVP_aes_256_cbc()
	case cipherAES128_ECB:
		cipher = C.go_openssl_EVP_aes_128_ecb()
	case cipherAES192_ECB:
		cipher = C.go_openssl_EVP_aes_192_ecb()
	case cipherAES256_ECB:
		cipher = C.go_openssl_EVP_aes_256_ecb()
	case cipherAES128_CTR:
		cipher = C.go_openssl_EVP_aes_128_ctr()
	case cipherAES192_CTR:
		cipher = C.go_openssl_EVP_aes_192_ctr()
	case cipherAES256_CTR:
		cipher = C.go_openssl_EVP_aes_256_ctr()
	case cipherAES128_GCM:
		cipher = C.go_openssl_EVP_aes_128_gcm()
	case cipherAES192_GCM:
		cipher = C.go_openssl_EVP_aes_192_gcm()
	case cipherAES256_GCM:
		cipher = C.go_openssl_EVP_aes_256_gcm()
	}
	return cipher
}

type aesKeySizeError int

func (k aesKeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

const aesBlockSize = 16

type aesCipher struct {
	key     []byte
	enc_ctx C.GO_EVP_CIPHER_CTX_PTR
	dec_ctx C.GO_EVP_CIPHER_CTX_PTR
	kind    cipherKind
}

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
	c := &aesCipher{key: make([]byte, len(key))}
	copy(c.key, key)

	switch len(c.key) * 8 {
	case 128:
		c.kind = cipherAES128_ECB
	case 192:
		c.kind = cipherAES192_ECB
	case 256:
		c.kind = cipherAES256_ECB
	default:
		return nil, errors.New("crypto/cipher: Invalid key size")
	}

	runtime.SetFinalizer(c, (*aesCipher).finalize)

	return c, nil
}

func (c *aesCipher) finalize() {
	if c.enc_ctx != nil {
		C.go_openssl_EVP_CIPHER_CTX_free(c.enc_ctx)
	}
	if c.dec_ctx != nil {
		C.go_openssl_EVP_CIPHER_CTX_free(c.dec_ctx)
	}
}

func (c *aesCipher) BlockSize() int { return aesBlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}
	// Only check for overlap between the parts of src and dst that will actually be used.
	// This matches Go standard library behavior.
	if inexactOverlap(dst[:aesBlockSize], src[:aesBlockSize]) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if c.enc_ctx == nil {
		var err error
		c.enc_ctx, err = newCipherCtx(c.kind, C.GO_AES_ENCRYPT, c.key, nil)
		if err != nil {
			panic(err)
		}
	}

	if C.go_openssl_EVP_EncryptUpdate_wrapper(c.enc_ctx, base(dst), base(src), aesBlockSize) != 1 {
		panic("crypto/cipher: EncryptUpdate failed")
	}
	runtime.KeepAlive(c)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}
	// Only check for overlap between the parts of src and dst that will actually be used.
	// This matches Go standard library behavior.
	if inexactOverlap(dst[:aesBlockSize], src[:aesBlockSize]) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if c.dec_ctx == nil {
		var err error
		c.dec_ctx, err = newCipherCtx(c.kind, C.GO_AES_DECRYPT, c.key, nil)
		if err != nil {
			panic(err)
		}
		if C.go_openssl_EVP_CIPHER_CTX_set_padding(c.dec_ctx, 0) != 1 {
			panic("crypto/cipher: could not disable cipher padding")
		}
	}

	C.go_openssl_EVP_DecryptUpdate_wrapper(c.dec_ctx, base(dst), base(src), aesBlockSize)
	runtime.KeepAlive(c)
}

type aesCBC struct {
	ctx C.GO_EVP_CIPHER_CTX_PTR
}

func (x *aesCBC) BlockSize() int { return aesBlockSize }

func (x *aesCBC) CryptBlocks(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src)%aesBlockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) > 0 {
		if C.go_openssl_EVP_CipherUpdate_wrapper(x.ctx, base(dst), base(src), C.int(len(src))) != 1 {
			panic("crypto/cipher: CipherUpdate failed")
		}
		runtime.KeepAlive(x)
	}
}

func (x *aesCBC) SetIV(iv []byte) {
	if len(iv) != aesBlockSize {
		panic("cipher: incorrect length IV")
	}
	if C.go_openssl_EVP_CipherInit_ex(x.ctx, nil, nil, nil, base(iv), -1) != 1 {
		panic("cipher: unable to initialize EVP cipher ctx")
	}
}

func (c *aesCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	x := new(aesCBC)

	var cipher cipherKind
	switch len(c.key) * 8 {
	case 128:
		cipher = cipherAES128_CBC
	case 192:
		cipher = cipherAES192_CBC
	case 256:
		cipher = cipherAES256_CBC
	default:
		panic("openssl: unsupported key length")
	}
	var err error
	x.ctx, err = newCipherCtx(cipher, C.GO_AES_ENCRYPT, c.key, iv)
	if err != nil {
		panic(err)
	}

	runtime.SetFinalizer(x, (*aesCBC).finalize)

	if C.go_openssl_EVP_CIPHER_CTX_set_padding(x.ctx, 0) != 1 {
		panic("cipher: unable to set padding")
	}
	return x
}

func (c *aesCBC) finalize() {
	C.go_openssl_EVP_CIPHER_CTX_free(c.ctx)
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	x := new(aesCBC)

	var cipher cipherKind
	switch len(c.key) * 8 {
	case 128:
		cipher = cipherAES128_CBC
	case 192:
		cipher = cipherAES192_CBC
	case 256:
		cipher = cipherAES256_CBC
	default:
		panic("openssl: unsupported key length")
	}

	var err error
	x.ctx, err = newCipherCtx(cipher, C.GO_AES_DECRYPT, c.key, iv)
	if err != nil {
		panic(err)
	}

	runtime.SetFinalizer(x, (*aesCBC).finalize)

	if C.go_openssl_EVP_CIPHER_CTX_set_padding(x.ctx, 0) != 1 {
		panic("cipher: unable to set padding")
	}
	return x
}

type aesCTR struct {
	ctx C.GO_EVP_CIPHER_CTX_PTR
}

func (x *aesCTR) XORKeyStream(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}
	if C.go_openssl_EVP_EncryptUpdate_wrapper(x.ctx, base(dst), base(src), C.int(len(src))) != 1 {
		panic("crypto/cipher: EncryptUpdate failed")
	}
	runtime.KeepAlive(x)
}

func (c *aesCipher) NewCTR(iv []byte) cipher.Stream {
	x := new(aesCTR)

	var cipher cipherKind
	switch len(c.key) * 8 {
	case 128:
		cipher = cipherAES128_CTR
	case 192:
		cipher = cipherAES192_CTR
	case 256:
		cipher = cipherAES256_CTR
	default:
		panic("openssl: unsupported key length")
	}
	var err error
	x.ctx, err = newCipherCtx(cipher, C.GO_AES_ENCRYPT, c.key, iv)
	if err != nil {
		panic(err)
	}

	runtime.SetFinalizer(x, (*aesCTR).finalize)

	return x
}

func (c *aesCTR) finalize() {
	C.go_openssl_EVP_CIPHER_CTX_free(c.ctx)
}

type aesGCM struct {
	ctx          C.GO_EVP_CIPHER_CTX_PTR
	tls          bool
	minNextNonce uint64
}

const (
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
	gcmTlsAddSize        = 13
	gcmTlsFixedNonceSize = 4
)

type aesNonceSizeError int

func (n aesNonceSizeError) Error() string {
	return "crypto/aes: invalid GCM nonce size " + strconv.Itoa(int(n))
}

type noGCM struct {
	cipher.Block
}

func (c *aesCipher) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize != gcmStandardNonceSize && tagSize != gcmTagSize {
		return nil, errors.New("crypto/aes: GCM tag and nonce sizes can't be non-standard at the same time")
	}
	// Fall back to standard library for GCM with non-standard nonce or tag size.
	if nonceSize != gcmStandardNonceSize {
		return cipher.NewGCMWithNonceSize(&noGCM{c}, nonceSize)
	}
	if tagSize != gcmTagSize {
		return cipher.NewGCMWithTagSize(&noGCM{c}, tagSize)
	}
	return c.newGCM(false)
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return c.(*aesCipher).NewGCMTLS()
}

func (c *aesCipher) NewGCMTLS() (cipher.AEAD, error) {
	return c.newGCM(true)
}

func (c *aesCipher) newGCM(tls bool) (cipher.AEAD, error) {
	var cipher cipherKind
	switch len(c.key) * 8 {
	case 128:
		cipher = cipherAES128_GCM
	case 192:
		cipher = cipherAES192_GCM
	case 256:
		cipher = cipherAES256_GCM
	default:
		panic("openssl: unsupported key length")
	}
	ctx, err := newCipherCtx(cipher, -1, c.key, nil)
	if err != nil {
		return nil, err
	}
	g := &aesGCM{ctx: ctx, tls: tls}
	runtime.SetFinalizer(g, (*aesGCM).finalize)
	return g, nil
}

func (g *aesGCM) finalize() {
	C.go_openssl_EVP_CIPHER_CTX_free(g.ctx)
}

func (g *aesGCM) NonceSize() int {
	return gcmStandardNonceSize
}

func (g *aesGCM) Overhead() int {
	return gcmTagSize
}

func (g *aesGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*aesBlockSize || len(plaintext)+gcmTagSize < len(plaintext) {
		panic("cipher: message too large for GCM")
	}
	if len(dst)+len(plaintext)+gcmTagSize < len(dst) {
		panic("cipher: message too large for buffer")
	}
	if g.tls {
		if len(additionalData) != gcmTlsAddSize {
			panic("cipher: incorrect additional data length given to GCM TLS")
		}
		// BoringCrypto enforces strictly monotonically increasing explicit nonces
		// and to fail after 2^64 - 1 keys as per FIPS 140-2 IG A.5,
		// but OpenSSL does not perform this check, so it is implemented here.
		const maxUint64 = 1<<64 - 1
		counter := binary.BigEndian.Uint64(nonce[gcmTlsFixedNonceSize:])
		if counter == maxUint64 {
			panic("cipher: nonce counter must be less than 2^64 - 1")
		}
		if counter < g.minNextNonce {
			panic("cipher: nonce counter must be strictly monotonically increasing")
		}
		defer func() {
			g.minNextNonce = counter + 1
		}()
	}

	// Make room in dst to append plaintext+overhead.
	ret, out := sliceForAppend(dst, len(plaintext)+gcmTagSize)

	// Check delayed until now to make sure len(dst) is accurate.
	if inexactOverlap(out, plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	// Encrypt additional data.
	// When sealing a TLS payload, OpenSSL app sets the additional data using
	// 'EVP_CIPHER_CTX_ctrl(g.ctx, C.EVP_CTRL_AEAD_TLS1_AAD, C.EVP_AEAD_TLS1_AAD_LEN, base(additionalData))'.
	// This makes the explicit nonce component to monotonically increase on every Seal operation without
	// relying in the explicit nonce being securely set externally,
	// and it also gives some interesting speed gains.
	// Unfortunately we can't use it because Go expects AEAD.Seal to honor the provided nonce.
	if C.go_openssl_EVP_CIPHER_CTX_seal_wrapper(g.ctx, base(out), base(nonce),
		base(plaintext), C.int(len(plaintext)),
		base(additionalData), C.int(len(additionalData))) != 1 {

		panic(fail("EVP_CIPHER_CTX_seal"))
	}
	runtime.KeepAlive(g)
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (g *aesGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*aesBlockSize+gcmTagSize {
		return nil, errOpen
	}
	// BoringCrypto does not do any TLS check when decrypting, neither do we.

	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	// Make room in dst to append ciphertext without tag.
	ret, out := sliceForAppend(dst, len(ciphertext))

	// Check delayed until now to make sure len(dst) is accurate.
	if inexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	ok := C.go_openssl_EVP_CIPHER_CTX_open_wrapper(
		g.ctx, base(out), base(nonce),
		base(ciphertext), C.int(len(ciphertext)),
		base(additionalData), C.int(len(additionalData)), base(tag))
	runtime.KeepAlive(g)
	if ok == 0 {
		// Zero output buffer on error.
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}

// sliceForAppend is a mirror of crypto/cipher.sliceForAppend.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func newCipherCtx(kind cipherKind, mode C.int, key, iv []byte) (C.GO_EVP_CIPHER_CTX_PTR, error) {
	cipher := newCipher(kind)
	if cipher == nil {
		panic("openssl: unsupported cipher: " + strconv.Itoa(int(kind)))
	}
	ctx := C.go_openssl_EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, fail("unable to create EVP cipher ctx")
	}
	if C.go_openssl_EVP_CipherInit_ex(ctx, cipher, nil, base(key), base(iv), mode) != 1 {
		C.go_openssl_EVP_CIPHER_CTX_free(ctx)
		return nil, fail("unable to initialize EVP cipher ctx")
	}
	return ctx, nil
}

// The following two functions are a mirror of golang.org/x/crypto/internal/subtle.

func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}
