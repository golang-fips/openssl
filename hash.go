//go:build !cmd_go_bootstrap

package openssl

import "C"
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

// maxHashSize is the size of SHA52 and SHA3_512, the largest hashes we support.
const maxHashSize = 64

func hashOneShot(ch crypto.Hash, p []byte, sum []byte) bool {
	_, err := ossl.EVP_Digest(pbaseNeverEmpty(p), len(p), base(sum), nil, loadHash(ch).md, nil)
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
	alg := loadHash(h)
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

func SHA3_224(p []byte) (sum [28]byte) {
	if !hashOneShot(crypto.SHA3_224, p, sum[:]) {
		panic("openssl: SHA3_224 failed")
	}
	return
}

func SHA3_256(p []byte) (sum [32]byte) {
	if !hashOneShot(crypto.SHA3_256, p, sum[:]) {
		panic("openssl: SHA3_256 failed")
	}
	return
}

func SHA3_384(p []byte) (sum [48]byte) {
	if !hashOneShot(crypto.SHA3_384, p, sum[:]) {
		panic("openssl: SHA3_384 failed")
	}
	return
}

func SHA3_512(p []byte) (sum [64]byte) {
	if !hashOneShot(crypto.SHA3_512, p, sum[:]) {
		panic("openssl: SHA3_512 failed")
	}
	return
}

// NewMD4 returns a new MD4 hash.
// The returned hash doesn't implement encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler.
func NewMD4() hash.Hash {
	return newEvpHash(crypto.MD4)
}

// NewMD5 returns a new MD5 hash.
func NewMD5() hash.Hash {
	return newEvpHash(crypto.MD5)
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return newEvpHash(crypto.SHA1)
}

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	return newEvpHash(crypto.SHA224)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return newEvpHash(crypto.SHA256)
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return newEvpHash(crypto.SHA384)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return newEvpHash(crypto.SHA512)
}

// NewSHA512_224 returns a new SHA512_224 hash.
func NewSHA512_224() hash.Hash {
	return newEvpHash(crypto.SHA512_224)
}

// NewSHA512_256 returns a new SHA512_256 hash.
func NewSHA512_256() hash.Hash {
	return newEvpHash(crypto.SHA512_256)
}

// NewSHA3_224 returns a new SHA3-224 hash.
func NewSHA3_224() hash.Hash {
	return newEvpHash(crypto.SHA3_224)
}

// NewSHA3_256 returns a new SHA3-256 hash.
func NewSHA3_256() hash.Hash {
	return newEvpHash(crypto.SHA3_256)
}

// NewSHA3_384 returns a new SHA3-384 hash.
func NewSHA3_384() hash.Hash {
	return newEvpHash(crypto.SHA3_384)
}

// NewSHA3_512 returns a new SHA3-512 hash.
func NewSHA3_512() hash.Hash {
	return newEvpHash(crypto.SHA3_512)
}

// isHashMarshallable returns true if the memory layout of md
// is known by this library and can therefore be marshalled.
func isHashMarshallable(md ossl.EVP_MD_PTR) bool {
	if vMajor == 1 {
		return true
	}
	prov := ossl.EVP_MD_get0_provider(md)
	if prov == nil {
		return false
	}
	cname := ossl.OSSL_PROVIDER_get0_name(prov)
	if cname == nil {
		return false
	}
	name := C.GoString((*C.char)(unsafe.Pointer(cname)))
	// We only know the memory layout of the built-in providers.
	// See evpHash.hashState for more details.
	marshallable := name == "default" || name == "fips"
	return marshallable
}

// cloneHash is an interface that defines a Clone method.
//
// hahs.CloneHash will probably be added in Go 1.25, see https://golang.org/issue/69521,
// but we need it now.
type cloneHash interface {
	hash.Hash
	// Clone returns a separate Hash instance with the same state as h.
	Clone() hash.Hash
}

var _ hash.Hash = (*evpHash)(nil)
var _ cloneHash = (*evpHash)(nil)

// evpHash implements generic hash methods.
type evpHash struct {
	alg *hashAlgorithm
	ctx ossl.EVP_MD_CTX_PTR
	// ctx2 is used in evpHash.sum to avoid changing
	// the state of ctx. Having it here allows reusing the
	// same allocated object multiple times.
	ctx2 ossl.EVP_MD_CTX_PTR
}

func newEvpHash(ch crypto.Hash) *evpHash {
	alg := loadHash(ch)
	if alg == nil {
		panic("openssl: unsupported hash function: " + strconv.Itoa(int(ch)))
	}
	h := &evpHash{alg: alg}
	// Don't call init() yet, it would be wasteful
	// if the caller only wants to know the hash type. This
	// is a common pattern in this package, as some functions
	// accept a `func() hash.Hash` parameter and call it just
	// to know the hash type.
	return h
}

func (h *evpHash) finalize() {
	if h.ctx != nil {
		ossl.EVP_MD_CTX_free(h.ctx)
	}
	if h.ctx2 != nil {
		ossl.EVP_MD_CTX_free(h.ctx2)
	}
}

func (h *evpHash) init() {
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
	runtime.SetFinalizer(h, (*evpHash).finalize)
}

func (h *evpHash) Reset() {
	if h.ctx == nil {
		// The hash is not initialized yet, no need to reset.
		return
	}
	// There is no need to reset h.ctx2 because it is always reset after
	// use in evpHash.sum.
	if _, err := ossl.EVP_DigestInit_ex(h.ctx, nil, nil); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	h.init()
	if _, err := ossl.EVP_DigestUpdate(h.ctx, pbase(p), len(p)); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	h.init()
	if _, err := ossl.EVP_DigestUpdate(h.ctx, unsafe.Pointer(unsafe.StringData(s)), len(s)); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	h.init()
	if _, err := ossl.EVP_DigestUpdate(h.ctx, unsafe.Pointer(&c), 1); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return nil
}

func (h *evpHash) Size() int {
	return h.alg.size
}

func (h *evpHash) BlockSize() int {
	return h.alg.blockSize
}

func (h *evpHash) Sum(in []byte) []byte {
	h.init()
	out := make([]byte, h.Size(), maxHashSize) // explicit cap to allow stack allocation
	if err := ossl.HashSum(h.ctx, h.ctx2, out); err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
	return append(in, out...)
}

// Clone returns a new evpHash object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *evpHash) Clone() hash.Hash {
	h2 := &evpHash{alg: h.alg}
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
		runtime.SetFinalizer(h2, (*evpHash).finalize)
	}
	runtime.KeepAlive(h)
	return h2
}

// hashState returns a pointer to the internal hash structure.
//
// The EVP_MD_CTX memory layout has changed in OpenSSL 3
// and the property holding the internal structure is no longer md_data but algctx.
func hashState(ctx ossl.EVP_MD_CTX_PTR) unsafe.Pointer {
	switch vMajor {
	case 1:
		// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/crypto/evp/evp_local.h#L12.
		type mdCtx struct {
			_       [2]unsafe.Pointer
			_       C.ulong
			md_data unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(ctx)).md_data
	case 3:
		// https://github.com/openssl/openssl/blob/5675a5aaf6a2e489022bcfc18330dae9263e598e/crypto/evp/evp_local.h#L16.
		type mdCtx struct {
			_      [3]unsafe.Pointer
			_      C.ulong
			_      [3]unsafe.Pointer
			algctx unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(ctx)).algctx
	default:
		panic(errUnsupportedVersion())
	}
}

func (d *evpHash) MarshalBinary() ([]byte, error) {
	if !d.alg.marshallable {
		return nil, errors.New("openssl: hash state is not marshallable")
	}
	buf := make([]byte, 0, d.alg.marshalledSize)
	return d.AppendBinary(buf)
}

func (d *evpHash) AppendBinary(buf []byte) ([]byte, error) {
	defer runtime.KeepAlive(d)
	d.init()
	if !d.alg.marshallable {
		return nil, errors.New("openssl: hash state is not marshallable")
	}
	state := hashState(d.ctx)
	if state == nil {
		return nil, errors.New("openssl: can't retrieve hash state")
	}
	var appender interface {
		AppendBinary([]byte) ([]byte, error)
	}
	switch d.alg.ch {
	case crypto.MD5:
		appender = (*md5State)(state)
	case crypto.SHA1:
		appender = (*sha1State)(state)
	case crypto.SHA224:
		appender = (*sha256State)(state)
	case crypto.SHA256:
		appender = (*sha256State)(state)
	case crypto.SHA384:
		appender = (*sha512State)(state)
	case crypto.SHA512:
		appender = (*sha512State)(state)
	case crypto.SHA512_224:
		appender = (*sha512State)(state)
	case crypto.SHA512_256:
		appender = (*sha512State)(state)
	default:
		panic("openssl: unsupported hash function: " + strconv.Itoa(int(d.alg.ch)))
	}
	buf = append(buf, d.alg.magic[:]...)
	return appender.AppendBinary(buf)
}

func (d *evpHash) UnmarshalBinary(b []byte) error {
	defer runtime.KeepAlive(d)
	d.init()
	if !d.alg.marshallable {
		return errors.New("openssl: hash state is not marshallable")
	}
	if len(b) < len(d.alg.magic) || string(b[:len(d.alg.magic)]) != string(d.alg.magic[:]) {
		return errors.New("openssl: invalid hash state identifier")
	}
	if len(b) != d.alg.marshalledSize {
		return errors.New("openssl: invalid hash state size")
	}
	state := hashState(d.ctx)
	if state == nil {
		return errors.New("openssl: can't retrieve hash state")
	}
	b = b[len(d.alg.magic):]
	var unmarshaler interface {
		UnmarshalBinary([]byte) error
	}
	switch d.alg.ch {
	case crypto.MD5:
		unmarshaler = (*md5State)(state)
	case crypto.SHA1:
		unmarshaler = (*sha1State)(state)
	case crypto.SHA224:
		unmarshaler = (*sha256State)(state)
	case crypto.SHA256:
		unmarshaler = (*sha256State)(state)
	case crypto.SHA384:
		unmarshaler = (*sha512State)(state)
	case crypto.SHA512:
		unmarshaler = (*sha512State)(state)
	case crypto.SHA512_224:
		unmarshaler = (*sha512State)(state)
	case crypto.SHA512_256:
		unmarshaler = (*sha512State)(state)
	default:
		panic("openssl: unsupported hash function: " + strconv.Itoa(int(d.alg.ch)))
	}
	return unmarshaler.UnmarshalBinary(b)
}

// md5State layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/md5.h#L33.
type md5State struct {
	h      [4]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

const (
	md5Magic         = "md5\x01"
	md5MarshaledSize = len(md5Magic) + 4*4 + 64 + 8
)

func (d *md5State) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (d *md5State) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// sha1State layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L34.
type sha1State struct {
	h      [5]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

const (
	sha1Magic         = "sha\x01"
	sha1MarshaledSize = len(sha1Magic) + 5*4 + 64 + 8
)

func (d *sha1State) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (d *sha1State) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = appendUint32(buf, d.h[4])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

const (
	magic224         = "sha\x02"
	magic256         = "sha\x03"
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8
)

// sha256State layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L51.
type sha256State struct {
	h      [8]uint32
	nl, nh uint32
	x      [64]byte
	nx     uint32
}

func (d *sha256State) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = uint32(n << 3)
	d.nh = uint32(n >> 29)
	d.nx = uint32(n) % 64
	return nil
}

func (d *sha256State) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint32(buf, d.h[0])
	buf = appendUint32(buf, d.h[1])
	buf = appendUint32(buf, d.h[2])
	buf = appendUint32(buf, d.h[3])
	buf = appendUint32(buf, d.h[4])
	buf = appendUint32(buf, d.h[5])
	buf = appendUint32(buf, d.h[6])
	buf = appendUint32(buf, d.h[7])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return buf, nil
}

// sha512State layout is taken from
// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/include/openssl/sha.h#L95.
type sha512State struct {
	h      [8]uint64
	nl, nh uint64
	x      [128]byte
	nx     uint32
}

const (
	magic384         = "sha\x04"
	magic512_224     = "sha\x05"
	magic512_256     = "sha\x06"
	magic512         = "sha\x07"
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8
)

func (d *sha512State) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, marshaledSize512)
	return d.AppendBinary(buf)
}

func (d *sha512State) UnmarshalBinary(b []byte) error {
	b, d.h[0] = consumeUint64(b)
	b, d.h[1] = consumeUint64(b)
	b, d.h[2] = consumeUint64(b)
	b, d.h[3] = consumeUint64(b)
	b, d.h[4] = consumeUint64(b)
	b, d.h[5] = consumeUint64(b)
	b, d.h[6] = consumeUint64(b)
	b, d.h[7] = consumeUint64(b)
	b = b[copy(d.x[:], b):]
	_, n := consumeUint64(b)
	d.nl = n << 3
	d.nh = n >> 61
	d.nx = uint32(n) % 128
	return nil
}

func (d *sha512State) AppendBinary(buf []byte) ([]byte, error) {
	buf = appendUint64(buf, d.h[0])
	buf = appendUint64(buf, d.h[1])
	buf = appendUint64(buf, d.h[2])
	buf = appendUint64(buf, d.h[3])
	buf = appendUint64(buf, d.h[4])
	buf = appendUint64(buf, d.h[5])
	buf = appendUint64(buf, d.h[6])
	buf = appendUint64(buf, d.h[7])
	buf = append(buf, d.x[:d.nx]...)
	buf = append(buf, make([]byte, len(d.x)-int(d.nx))...)
	buf = appendUint64(buf, d.nl>>3|d.nh<<61)
	return buf, nil
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
