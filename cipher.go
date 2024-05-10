//go:build !cmd_go_bootstrap

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
	cipherAES128 cipherKind = iota
	cipherAES192
	cipherAES256
	cipherDES
	cipherDES3
	cipherRC4
)

func (c cipherKind) String() string {
	switch c {
	case cipherAES128:
		return "AES-128"
	case cipherAES192:
		return "AES-192"
	case cipherAES256:
		return "AES-256"
	case cipherDES:
		return "DES"
	case cipherDES3:
		return "DES3"
	case cipherRC4:
		return "RC4"
	default:
		panic("unknown cipher kind: " + strconv.Itoa(int(c)))
	}
}

type cipherMode int8

const (
	cipherModeNone cipherMode = -1
	cipherModeECB  cipherMode = iota
	cipherModeCBC
	cipherModeCTR
	cipherModeGCM
)

// cipherOp is the allowed operations for a cipher,
// as documented in [EVP_CipherInit_ex].
//
// [EVP_CipherInit_ex]: https://www.openssl.org/docs/man3.0/man3/EVP_CipherInit_ex.html
type cipherOp int8

const (
	cipherOpNone    cipherOp = -1 // leaves the value of the previous call, if any.
	cipherOpDecrypt cipherOp = 0
	cipherOpEncrypt cipherOp = 1
)

// cacheCipher is a cache of cipherKind to GO_EVP_CIPHER_PTR.
var cacheCipher sync.Map

type cacheCipherKey struct {
	kind cipherKind
	mode cipherMode
}

// loadCipher returns a cipher object for the given k.
func loadCipher(k cipherKind, mode cipherMode) (cipher C.GO_EVP_CIPHER_PTR) {
	if v, ok := cacheCipher.Load(cacheCipherKey{k, mode}); ok {
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
		cacheCipher.Store(cacheCipherKey{k, mode}, cipher)
	}()
	switch k {
	case cipherAES128:
		switch mode {
		case cipherModeECB:
			cipher = C.go_openssl_EVP_aes_128_ecb()
		case cipherModeCBC:
			cipher = C.go_openssl_EVP_aes_128_cbc()
		case cipherModeCTR:
			cipher = C.go_openssl_EVP_aes_128_ctr()
		case cipherModeGCM:
			cipher = C.go_openssl_EVP_aes_128_gcm()
		}
	case cipherAES192:
		switch mode {
		case cipherModeECB:
			cipher = C.go_openssl_EVP_aes_192_ecb()
		case cipherModeCBC:
			cipher = C.go_openssl_EVP_aes_192_cbc()
		case cipherModeCTR:
			cipher = C.go_openssl_EVP_aes_192_ctr()
		case cipherModeGCM:
			cipher = C.go_openssl_EVP_aes_192_gcm()
		}
	case cipherAES256:
		switch mode {
		case cipherModeECB:
			cipher = C.go_openssl_EVP_aes_256_ecb()
		case cipherModeCBC:
			cipher = C.go_openssl_EVP_aes_256_cbc()
		case cipherModeCTR:
			cipher = C.go_openssl_EVP_aes_256_ctr()
		case cipherModeGCM:
			cipher = C.go_openssl_EVP_aes_256_gcm()
		}
	case cipherDES:
		switch mode {
		case cipherModeECB:
			cipher = C.go_openssl_EVP_des_ecb()
		case cipherModeCBC:
			cipher = C.go_openssl_EVP_des_cbc()
		}
	case cipherDES3:
		switch mode {
		case cipherModeECB:
			cipher = C.go_openssl_EVP_des_ede3_ecb()
		case cipherModeCBC:
			cipher = C.go_openssl_EVP_des_ede3_cbc()
		}
	case cipherRC4:
		cipher = C.go_openssl_EVP_rc4()
	}
	return cipher
}

type evpCipher struct {
	key       []byte
	encLock   sync.Mutex
	enc_ctx   C.GO_EVP_CIPHER_CTX_PTR
	decLock   sync.Mutex
	dec_ctx   C.GO_EVP_CIPHER_CTX_PTR
	kind      cipherKind
	blockSize int
}

func newEVPCipher(key []byte, kind cipherKind) (*evpCipher, error) {
	cipher := loadCipher(kind, cipherModeECB)
	if cipher == nil {
		return nil, errors.New("crypto/cipher: unsupported cipher: " + kind.String())
	}
	c := &evpCipher{key: make([]byte, len(key)), kind: kind}
	copy(c.key, key)
	c.blockSize = int(C.go_openssl_EVP_CIPHER_get_block_size(cipher))
	runtime.SetFinalizer(c, (*evpCipher).finalize)
	return c, nil
}

func (c *evpCipher) finalize() {
	if c.enc_ctx != nil {
		C.go_openssl_EVP_CIPHER_CTX_free(c.enc_ctx)
	}
	if c.dec_ctx != nil {
		C.go_openssl_EVP_CIPHER_CTX_free(c.dec_ctx)
	}
}

func (c *evpCipher) encrypt(dst, src []byte) error {
	if len(src) < c.blockSize {
		return errors.New("input not full block")
	}
	if len(dst) < c.blockSize {
		return errors.New("output not full block")
	}
	// Only check for overlap between the parts of src and dst that will actually be used.
	// This matches Go standard library behavior.
	if inexactOverlap(dst[:c.blockSize], src[:c.blockSize]) {
		return errors.New("invalid buffer overlap")
	}
	c.encLock.Lock()
	defer c.encLock.Unlock()
	if c.enc_ctx == nil {
		var err error
		c.enc_ctx, err = newCipherCtx(c.kind, cipherModeECB, cipherOpEncrypt, c.key, nil)
		if err != nil {
			return err
		}
	}

	if C.go_openssl_EVP_EncryptUpdate_wrapper(c.enc_ctx, base(dst), base(src), C.int(c.blockSize)) != 1 {
		return errors.New("EncryptUpdate failed")
	}
	runtime.KeepAlive(c)
	return nil
}

func (c *evpCipher) decrypt(dst, src []byte) error {
	if len(src) < c.blockSize {
		return errors.New("input not full block")
	}
	if len(dst) < c.blockSize {
		return errors.New("output not full block")
	}
	// Only check for overlap between the parts of src and dst that will actually be used.
	// This matches Go standard library behavior.
	if inexactOverlap(dst[:c.blockSize], src[:c.blockSize]) {
		return errors.New("invalid buffer overlap")
	}
	c.decLock.Lock()
	defer c.decLock.Unlock()
	if c.dec_ctx == nil {
		var err error
		c.dec_ctx, err = newCipherCtx(c.kind, cipherModeECB, cipherOpDecrypt, c.key, nil)
		if err != nil {
			return err
		}
		if C.go_openssl_EVP_CIPHER_CTX_set_padding(c.dec_ctx, 0) != 1 {
			return errors.New("could not disable cipher padding")
		}
	}

	C.go_openssl_EVP_DecryptUpdate_wrapper(c.dec_ctx, base(dst), base(src), C.int(c.blockSize))
	runtime.KeepAlive(c)
	return nil
}

type cipherCBC struct {
	ctx       C.GO_EVP_CIPHER_CTX_PTR
	ctxLock   sync.Mutex
	blockSize int
}

func (c *cipherCBC) finalize() {
	C.go_openssl_EVP_CIPHER_CTX_free(c.ctx)
}

func (x *cipherCBC) BlockSize() int { return x.blockSize }

func (x *cipherCBC) CryptBlocks(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) > 0 {
		x.ctxLock.Lock()
		defer x.ctxLock.Unlock()
		if C.go_openssl_EVP_CipherUpdate_wrapper(x.ctx, base(dst), base(src), C.int(len(src))) != 1 {
			panic("crypto/cipher: CipherUpdate failed")
		}
		runtime.KeepAlive(x)
	}
}

func (x *cipherCBC) SetIV(iv []byte) {
	if len(iv) != x.blockSize {
		panic("cipher: incorrect length IV")
	}
	x.ctxLock.Lock()
	defer x.ctxLock.Unlock()
	if C.go_openssl_EVP_CipherInit_ex(x.ctx, nil, nil, nil, base(iv), C.int(cipherOpNone)) != 1 {
		panic("cipher: unable to initialize EVP cipher ctx")
	}
}

func (c *evpCipher) newCBC(iv []byte, op cipherOp) cipher.BlockMode {
	ctx, err := newCipherCtx(c.kind, cipherModeCBC, op, c.key, iv)
	if err != nil {
		panic(err)
	}
	x := &cipherCBC{ctx: ctx, blockSize: c.blockSize}
	runtime.SetFinalizer(x, (*cipherCBC).finalize)
	if C.go_openssl_EVP_CIPHER_CTX_set_padding(x.ctx, 0) != 1 {
		panic("cipher: unable to set padding")
	}
	return x
}

type cipherCTR struct {
	ctx     C.GO_EVP_CIPHER_CTX_PTR
	ctxLock sync.Mutex
}

func (x *cipherCTR) XORKeyStream(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}
	x.ctxLock.Lock()
	defer x.ctxLock.Unlock()
	if C.go_openssl_EVP_EncryptUpdate_wrapper(x.ctx, base(dst), base(src), C.int(len(src))) != 1 {
		panic("crypto/cipher: EncryptUpdate failed")
	}
	runtime.KeepAlive(x)
}

func (c *evpCipher) newCTR(iv []byte) cipher.Stream {
	ctx, err := newCipherCtx(c.kind, cipherModeCTR, cipherOpEncrypt, c.key, iv)
	if err != nil {
		panic(err)
	}
	x := &cipherCTR{ctx: ctx}
	runtime.SetFinalizer(x, (*cipherCTR).finalize)
	return x
}

func (c *cipherCTR) finalize() {
	C.go_openssl_EVP_CIPHER_CTX_free(c.ctx)
}

type cipherGCMTLS uint8

const (
	cipherGCMTLSNone cipherGCMTLS = iota
	cipherGCMTLS12
	cipherGCMTLS13
)

type cipherGCM struct {
	ctx     C.GO_EVP_CIPHER_CTX_PTR
	ctxLock sync.Mutex
	tls     cipherGCMTLS
	// minNextNonce is the minimum value that the next nonce can be, enforced by
	// all TLS modes.
	minNextNonce uint64
	// mask is the nonce mask used in TLS 1.3 mode.
	mask uint64
	// maskInitialized is true if mask has been initialized. This happens during
	// the first Seal. The initialized mask may be 0. Used by TLS 1.3 mode.
	maskInitialized bool
	blockSize       int
}

const (
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
	// TLS 1.2 additional data is constructed as:
	//
	//     additional_data = seq_num(8) + TLSCompressed.type(1) + TLSCompressed.version(2) + TLSCompressed.length(2);
	gcmTls12AddSize = 13
	// TLS 1.3 additional data is constructed as:
	//
	//     additional_data = TLSCiphertext.opaque_type(1) || TLSCiphertext.legacy_record_version(2) || TLSCiphertext.length(2)
	gcmTls13AddSize      = 5
	gcmTlsFixedNonceSize = 4
)

type noGCM struct {
	*evpCipher
}

func (g *noGCM) BlockSize() int {
	return g.blockSize
}

func (g *noGCM) Encrypt(dst, src []byte) {
	g.encrypt(dst, src)
}

func (g *noGCM) Decrypt(dst, src []byte) {
	g.decrypt(dst, src)
}

func (c *evpCipher) newGCMChecked(nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize != gcmStandardNonceSize && tagSize != gcmTagSize {
		return nil, errors.New("crypto/cipher: GCM tag and nonce sizes can't be non-standard at the same time")
	}
	// Fall back to standard library for GCM with non-standard nonce or tag size.
	if nonceSize != gcmStandardNonceSize {
		return cipher.NewGCMWithNonceSize(&noGCM{c}, nonceSize)
	}
	if tagSize != gcmTagSize {
		return cipher.NewGCMWithTagSize(&noGCM{c}, tagSize)
	}
	return c.newGCM(cipherGCMTLSNone)
}

func (c *evpCipher) newGCM(tls cipherGCMTLS) (cipher.AEAD, error) {
	ctx, err := newCipherCtx(c.kind, cipherModeGCM, cipherOpNone, c.key, nil)
	if err != nil {
		return nil, err
	}
	g := &cipherGCM{ctx: ctx, tls: tls, blockSize: c.blockSize}
	runtime.SetFinalizer(g, (*cipherGCM).finalize)
	return g, nil
}

func (g *cipherGCM) finalize() {
	C.go_openssl_EVP_CIPHER_CTX_free(g.ctx)
}

func (g *cipherGCM) NonceSize() int {
	return gcmStandardNonceSize
}

func (g *cipherGCM) Overhead() int {
	return gcmTagSize
}

func (g *cipherGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*uint64(g.blockSize) || len(plaintext)+gcmTagSize < len(plaintext) {
		panic("cipher: message too large for GCM")
	}
	if len(dst)+len(plaintext)+gcmTagSize < len(dst) {
		panic("cipher: message too large for buffer")
	}
	if g.tls != cipherGCMTLSNone {
		if g.tls == cipherGCMTLS12 && len(additionalData) != gcmTls12AddSize {
			panic("cipher: incorrect additional data length given to GCM TLS 1.2")
		} else if g.tls == cipherGCMTLS13 && len(additionalData) != gcmTls13AddSize {
			panic("cipher: incorrect additional data length given to GCM TLS 1.3")
		}
		counter := binary.BigEndian.Uint64(nonce[gcmTlsFixedNonceSize:])
		if g.tls == cipherGCMTLS13 {
			// In TLS 1.3, the counter in the nonce has a mask and requires
			// further decoding.
			if !g.maskInitialized {
				// According to TLS 1.3 nonce construction details at
				// https://tools.ietf.org/html/rfc8446#section-5.3:
				//
				//   the first record transmitted under a particular traffic
				//   key MUST use sequence number 0.
				//
				//   The padded sequence number is XORed with [a mask].
				//
				//   The resulting quantity (of length iv_length) is used as
				//   the per-record nonce.
				//
				// We need to convert from the given nonce to sequence numbers
				// to keep track of minNextNonce and enforce the counter
				// maximum. On the first call, we know counter^mask is 0^mask,
				// so we can simply store it as the mask.
				g.mask = counter
				g.maskInitialized = true
			}
			counter ^= g.mask
		}
		// BoringCrypto enforces strictly monotonically increasing explicit nonces
		// and to fail after 2^64 - 1 keys as per FIPS 140-2 IG A.5,
		// but OpenSSL does not perform this check, so it is implemented here.
		const maxUint64 = 1<<64 - 1
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
	g.ctxLock.Lock()
	defer g.ctxLock.Unlock()
	if C.go_openssl_EVP_CIPHER_CTX_seal_wrapper(g.ctx, base(out), base(nonce),
		base(plaintext), C.int(len(plaintext)),
		base(additionalData), C.int(len(additionalData))) != 1 {

		panic(fail("EVP_CIPHER_CTX_seal"))
	}
	runtime.KeepAlive(g)
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (g *cipherGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(g.blockSize)+gcmTagSize {
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

	g.ctxLock.Lock()
	defer g.ctxLock.Unlock()
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

func newCipherCtx(kind cipherKind, mode cipherMode, encrypt cipherOp, key, iv []byte) (_ C.GO_EVP_CIPHER_CTX_PTR, err error) {
	cipher := loadCipher(kind, mode)
	if cipher == nil {
		panic("crypto/cipher: unsupported cipher: " + kind.String())
	}
	ctx := C.go_openssl_EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, fail("unable to create EVP cipher ctx")
	}
	defer func() {
		if err != nil {
			C.go_openssl_EVP_CIPHER_CTX_free(ctx)
		}
	}()
	if kind == cipherRC4 {
		// RC4 cipher supports a variable key length.
		// We need to set the key length before setting the key,
		// and to do so we need to have an initialized cipher ctx.
		if C.go_openssl_EVP_CipherInit_ex(ctx, cipher, nil, nil, nil, C.int(encrypt)) != 1 {
			return nil, newOpenSSLError("EVP_CipherInit_ex")
		}
		if C.go_openssl_EVP_CIPHER_CTX_set_key_length(ctx, C.int(len(key))) != 1 {
			return nil, newOpenSSLError("EVP_CIPHER_CTX_set_key_length")
		}
		// Pass nil to the next call to EVP_CipherInit_ex to avoid resetting ctx's cipher.
		cipher = nil
	}
	if C.go_openssl_EVP_CipherInit_ex(ctx, cipher, nil, base(key), base(iv), C.int(encrypt)) != 1 {
		return nil, newOpenSSLError("unable to initialize EVP cipher ctx")
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
