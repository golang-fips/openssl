//go:build !cmd_go_bootstrap && (cgo || goexperiment.ms_nocgo_opensslcrypto)

package openssl

import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"strconv"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

const (
	magicMD5     = "md5\x01"
	magic1       = "sha\x01"
	magic224     = "sha\x02"
	magic256     = "sha\x03"
	magic384     = "sha\x04"
	magic512_224 = "sha\x05"
	magic512_256 = "sha\x06"
	magic512     = "sha\x07"

	marshaledSizeMD5 = len(magicMD5) + 4*4 + 64 + 8  // from crypto/md5
	marshaledSize1   = len(magic1) + 5*4 + 64 + 8    // from crypto/sha1
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8  // from crypto/sha256
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8 // from crypto/sha512
)

// maxHashSize is the size of SHA52 and SHA3_512, the largest hashes we support.
const maxHashSize = 64

func hashOneShot(ch crypto.Hash, p []byte, sum []byte) bool {
	_, err := ossl.EVP_Digest(p, sum, nil, loadHash(ch, true).md, nil)
	return err == nil
}

func MD4(p []byte) (sum [16]byte) {
	if !hashOneShot(crypto.MD4, p, sum[:]) {
		panic("openssl: MD4 failed")
	}
	return
}

func MD5(p []byte) (sum [16]byte) {
	if !hashOneShot(crypto.MD5, p, sum[:]) {
		panic("openssl: MD5 failed")
	}
	return
}

func SHA1(p []byte) (sum [20]byte) {
	if !hashOneShot(crypto.SHA1, p, sum[:]) {
		panic("openssl: SHA1 failed")
	}
	return
}

func SHA224(p []byte) (sum [28]byte) {
	if !hashOneShot(crypto.SHA224, p, sum[:]) {
		panic("openssl: SHA224 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if !hashOneShot(crypto.SHA256, p, sum[:]) {
		panic("openssl: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if !hashOneShot(crypto.SHA384, p, sum[:]) {
		panic("openssl: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if !hashOneShot(crypto.SHA512, p, sum[:]) {
		panic("openssl: SHA512 failed")
	}
	return
}

func SHA512_224(p []byte) (sum [28]byte) {
	if !hashOneShot(crypto.SHA512_224, p, sum[:]) {
		panic("openssl: SHA512 failed")
	}
	return
}

func SHA512_256(p []byte) (sum [32]byte) {
	if !hashOneShot(crypto.SHA512_256, p, sum[:]) {
		panic("openssl: SHA512_256 failed")
	}
	return
}

// cacheHashSupported is a cache of crypto.Hash support.
var cacheHashSupported sync.Map

// SupportsHash reports whether the current OpenSSL version supports the given hash.
func SupportsHash(h crypto.Hash) bool {
	if v, ok := cacheHashSupported.Load(h); ok {
		return v.(bool)
	}
	alg := loadHash(h, false)
	if alg == nil {
		cacheHashSupported.Store(h, false)
		return false
	}
	// EVP_MD objects can be non-nil even when they can't be used
	// in a EVP_MD_CTX, e.g. MD5 in FIPS mode. We need to prove
	// if they can be used by passing them to a EVP_MD_CTX.
	var supported bool
	if ctx, _ := ossl.EVP_MD_CTX_new(); ctx != nil {
		_, err := ossl.EVP_DigestInit_ex(ctx, alg.md, nil)
		supported = err == nil
		ossl.EVP_MD_CTX_free(ctx)
	}
	cacheHashSupported.Store(h, supported)
	return supported
}

func SumSHA3_224(p []byte) (sum [28]byte) {
	if !hashOneShot(crypto.SHA3_224, p, sum[:]) {
		panic("openssl: SHA3_224 failed")
	}
	return
}

func SumSHA3_256(p []byte) (sum [32]byte) {
	if !hashOneShot(crypto.SHA3_256, p, sum[:]) {
		panic("openssl: SHA3_256 failed")
	}
	return
}

func SumSHA3_384(p []byte) (sum [48]byte) {
	if !hashOneShot(crypto.SHA3_384, p, sum[:]) {
		panic("openssl: SHA3_384 failed")
	}
	return
}

func SumSHA3_512(p []byte) (sum [64]byte) {
	if !hashOneShot(crypto.SHA3_512, p, sum[:]) {
		panic("openssl: SHA3_512 failed")
	}
	return
}

// NewMD4 returns a new MD4 hash.
// The returned hash doesn't implement encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler.
func NewMD4() hash.Hash {
	return newHash(crypto.MD4)
}

// NewMD5 returns a new MD5 hash.
func NewMD5() hash.Hash {
	return newHash(crypto.MD5)
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return newHash(crypto.SHA1)
}

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	return newHash(crypto.SHA224)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return newHash(crypto.SHA256)
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return newHash(crypto.SHA384)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return newHash(crypto.SHA512)
}

// NewSHA512_224 returns a new SHA512_224 hash.
func NewSHA512_224() hash.Hash {
	return newHash(crypto.SHA512_224)
}

// NewSHA512_256 returns a new SHA512_256 hash.
func NewSHA512_256() hash.Hash {
	return newHash(crypto.SHA512_256)
}

// NewSHA3_224 returns a new SHA3-224 hash.
func NewSHA3_224() *Hash {
	return newHash(crypto.SHA3_224)
}

// NewSHA3_256 creates a new SHA3-256 hash.
func NewSHA3_256() *Hash {
	return newHash(crypto.SHA3_256)
}

// NewSHA3_384 creates a new SHA3-384 hash.
func NewSHA3_384() *Hash {
	return newHash(crypto.SHA3_384)
}

// NewSHA3_512 creates a new SHA3-512 hash.
func NewSHA3_512() *Hash {
	return newHash(crypto.SHA3_512)
}

var _ hash.Hash = (*Hash)(nil)
var _ HashCloner = (*Hash)(nil)

// hashBufSize is the size of the buffer used for hashing.
// 256 bytes is a reasonable compromise for general purpose use,
// and the resulting evpHash size is still similar to the
// upstream sha512 hash object.
const hashBufSize = 256

// Hash implements generic hash methods.
type Hash struct {
	alg *hashAlgorithm
	ctx ossl.EVP_MD_CTX_PTR
	// ctx2 is used in Hash.Sum to avoid changing
	// the state of ctx. Having it here allows reusing the
	// same allocated object multiple times.
	ctx2 ossl.EVP_MD_CTX_PTR

	// buf is a buffer for data not yet written to ctx.
	// It is used to reduce calls into OpenSSL for small writes.
	// The buffer size is a trade-off between memory usage and
	// number of calls into OpenSSL.
	buf  [hashBufSize]byte
	nbuf int
}

func newHash(ch crypto.Hash) *Hash {
	// Don't call init() yet, it would be wasteful
	// if the caller only wants to know the hash type. This
	// is a common pattern in this package, as some functions
	// accept a `func() hash.Hash` parameter and call it just
	// to know the hash type.
	return &Hash{alg: loadHash(ch, true)}
}

func (h *Hash) finalize() {
	if h.ctx != nil {
		ossl.EVP_MD_CTX_free(h.ctx)
	}
	if h.ctx2 != nil {
		ossl.EVP_MD_CTX_free(h.ctx2)
	}
}

func (h *Hash) init() {
	if h.ctx != nil {
		return
	}
	var err error
	h.ctx, err = ossl.EVP_MD_CTX_new()
	if err != nil {
		panic(err)
	}
	if _, err := ossl.EVP_DigestInit_ex(h.ctx, h.alg.md, nil); err != nil {
		ossl.EVP_MD_CTX_free(h.ctx)
		panic(err)
	}
	h.ctx2, err = ossl.EVP_MD_CTX_new()
	if err != nil {
		ossl.EVP_MD_CTX_free(h.ctx)
		panic(err)
	}
	runtime.SetFinalizer(h, (*Hash).finalize)
}

func (h *Hash) write(p []byte) int {
	if len(p) == 0 {
		return 0
	}
	if h.nbuf > 0 && h.nbuf+len(p) > len(h.buf) {
		// We have buffered data and adding p would exceed the buffer,
		// flush the buffer first.
		h.flush()
	}
	if len(p) > len(h.buf) {
		// p is larger than the buffer, write it directly.
		h.init()
		if _, err := ossl.EVP_DigestUpdate(h.ctx, p); err != nil {
			panic(err)
		}
	} else {
		// Otherwise, buffer it.
		h.nbuf += copy(h.buf[h.nbuf:], p)
	}
	runtime.KeepAlive(h)
	return len(p)
}

func (h *Hash) flush() {
	h.init()
	if h.nbuf > 0 {
		if _, err := ossl.EVP_DigestUpdate(h.ctx, h.buf[:h.nbuf]); err != nil {
			panic(err)
		}
		h.nbuf = 0
	}
}

func (h *Hash) Reset() {
	h.nbuf = 0
	if h.ctx == nil {
		// The hash is not initialized yet, no need to reset ctx.
		return
	}
	// There is no need to reset h.ctx2 because it is always reset in evpHash.Sum.
	if _, err := ossl.EVP_DigestInit_ex(h.ctx, nil, nil); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
}

func (h *Hash) Write(p []byte) (int, error) {
	return h.write(p), nil
}

func (h *Hash) WriteString(s string) (int, error) {
	return h.write(unsafe.Slice(unsafe.StringData(s), len(s))), nil
}

func (h *Hash) WriteByte(c byte) error {
	h.write(unsafe.Slice(&c, 1))
	return nil
}

func (h *Hash) Size() int {
	return h.alg.size
}

func (h *Hash) BlockSize() int {
	return h.alg.blockSize
}

func (h *Hash) Sum(in []byte) []byte {
	out := append(in, make([]byte, h.Size(), maxHashSize)...)
	if h.ctx == nil {
		// Fast path: if ctx hasn't been initialized, all data is in the buffer
		// and we can use the one-shot EVP_Digest function.
		if _, err := ossl.EVP_Digest(h.buf[:h.nbuf], out[len(in):], nil, h.alg.md, nil); err != nil {
			panic(err)
		}
		return out
	}
	// Slow path: copy h.ctx into h.ctx2 and call EVP_DigestFinal_ex using h.ctx2.
	// This is necessary because Go hash.Hash mandates that Sum has no effect
	// on the underlying stream. In particular it is OK to Sum, then Write more,
	// then Sum again, and the second Sum acts as if the first didn't happen.
	if _, err := ossl.EVP_MD_CTX_copy_ex(h.ctx2, h.ctx); err != nil {
		panic(err)
	}
	if h.nbuf > 0 {
		// If we have buffered data, update ctx2 with it
		if _, err := ossl.EVP_DigestUpdate(h.ctx2, h.buf[:h.nbuf]); err != nil {
			panic(err)
		}
	}
	if _, err := ossl.EVP_DigestFinal_ex(h.ctx2, out[len(in):], nil); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return out
}

// Clone returns a new Hash object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *Hash) Clone() (HashCloner, error) {
	h2 := &Hash{alg: h.alg, nbuf: h.nbuf}
	copy(h2.buf[:h.nbuf], h.buf[:h.nbuf])
	if h.ctx != nil {
		var err error
		h2.ctx, err = ossl.EVP_MD_CTX_new()
		if err != nil {
			panic(err)
		}
		if _, err := ossl.EVP_MD_CTX_copy_ex(h2.ctx, h.ctx); err != nil {
			ossl.EVP_MD_CTX_free(h2.ctx)
			panic(err)
		}
		h2.ctx2, err = ossl.EVP_MD_CTX_new()
		if err != nil {
			ossl.EVP_MD_CTX_free(h2.ctx)
			panic(err)
		}
		runtime.SetFinalizer(h2, (*Hash).finalize)
	}
	runtime.KeepAlive(h)
	return h2, nil
}

type errMarshallUnsupported struct{}

func (e errMarshallUnsupported) Error() string {
	return "cryptokit: hash state is not marshallable"
}

func (e errMarshallUnsupported) Unwrap() error {
	return errors.ErrUnsupported
}

func (d *Hash) MarshalBinary() ([]byte, error) {
	if d.alg == nil || !d.alg.marshallable {
		return nil, errMarshallUnsupported{}
	}
	buf := make([]byte, 0, d.alg.marshalledSize)
	return d.AppendBinary(buf)
}

func (d *Hash) AppendBinary(buf []byte) ([]byte, error) {
	defer runtime.KeepAlive(d)
	if d.alg == nil || !d.alg.marshallable {
		return nil, errMarshallUnsupported{}
	}
	d.flush()
	switch d.alg.provider {
	case providerOSSLDefault, providerOSSLFIPS:
		return osslHashAppendBinary(d.ctx, d.alg.ch, d.alg.magic, buf)
	case providerSymCrypt:
		return symCryptHashAppendBinary(d.ctx, d.alg.ch, d.alg.magic, buf)
	default:
		panic("openssl: unknown hash provider" + strconv.Itoa(int(d.alg.provider)))
	}
}

func (d *Hash) UnmarshalBinary(b []byte) error {
	defer runtime.KeepAlive(d)
	d.flush()
	if d.alg == nil || !d.alg.marshallable {
		return errMarshallUnsupported{}
	}
	if len(b) < len(d.alg.magic) || string(b[:len(d.alg.magic)]) != d.alg.magic {
		return errors.New("openssl: invalid hash state identifier")
	}
	if len(b) != d.alg.marshalledSize {
		return errors.New("openssl: invalid hash state size")
	}
	switch d.alg.provider {
	case providerOSSLDefault, providerOSSLFIPS:
		return osslHashUnmarshalBinary(d.ctx, d.alg.ch, d.alg.magic, b)
	case providerSymCrypt:
		return symCryptHashUnmarshalBinary(d.ctx, d.alg.ch, d.alg.magic, b)
	default:
		panic("openssl: unknown hash provider" + strconv.Itoa(int(d.alg.provider)))
	}
}

// appendUint64 appends x into b as a big endian byte sequence.
func appendUint64(b []byte, x uint64) []byte {
	return append(b,
		byte(x>>56),
		byte(x>>48),
		byte(x>>40),
		byte(x>>32),
		byte(x>>24),
		byte(x>>16),
		byte(x>>8),
		byte(x),
	)
}

// appendUint32 appends x into b as a big endian byte sequence.
func appendUint32(b []byte, x uint32) []byte {
	return append(b, byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}

// consumeUint64 reads a big endian uint64 number from b.
func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

// consumeUint32 reads a big endian uint32 number from b.
func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}
