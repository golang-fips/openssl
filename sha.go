//go:build linux
// +build linux

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"strconv"
	"unsafe"
)

// NOTE: Implementation ported from https://go-review.googlesource.com/c/go/+/404295.
// The cgo calls in this file are arranged to avoid marking the parameters as escaping.
// To do that, we call noescape (including via addr).
// We must also make sure that the data pointer arguments have the form unsafe.Pointer(&...)
// so that cgo does not annotate them with cgoCheckPointer calls. If it did that, it might look
// beyond the byte slice and find Go pointers in unprocessed parts of a larger allocation.
// To do both of these simultaneously, the idiom is unsafe.Pointer(&*addr(p)),
// where addr returns the base pointer of p, substituting a non-nil pointer for nil,
// and applying a noescape along the way.
// This is all to preserve compatibility with the allocation behavior of the non-openssl implementations.

func shaX(ch crypto.Hash, p []byte, sum []byte) bool {
	return C.go_openssl_EVP_Digest(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), (*C.uchar)(unsafe.Pointer(&*addr(sum))), nil, cryptoHashToMD(ch), nil) != 0
}

func SHA1(p []byte) (sum [20]byte) {
	if !shaX(crypto.SHA1, p, sum[:]) {
		panic("openssl: SHA1 failed")
	}
	return
}

func SHA224(p []byte) (sum [28]byte) {
	if !shaX(crypto.SHA224, p, sum[:]) {
		panic("openssl: SHA224 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if !shaX(crypto.SHA256, p, sum[:]) {
		panic("openssl: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if !shaX(crypto.SHA384, p, sum[:]) {
		panic("openssl: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if !shaX(crypto.SHA512, p, sum[:]) {
		panic("openssl: SHA512 failed")
	}
	return
}

// Same as SupportsHKDF, as in v1.1.1+
func SupportsSHA3() bool {
	return vMajor > 1 ||
		(vMajor >= 1 && vMinor > 1) ||
		(vMajor >= 1 && vMinor >= 1 && vPatch >= 1)
}

func SHA3_224(p []byte) (sum [28]byte) {
	if !shaX(crypto.SHA3_224, p, sum[:]) {
		panic("openssl: SHA3_224 failed")
	}
	return
}

func SHA3_256(p []byte) (sum [32]byte) {
	if !shaX(crypto.SHA3_256, p, sum[:]) {
		panic("openssl: SHA3_256 failed")
	}
	return
}

func SHA3_384(p []byte) (sum [48]byte) {
	if !shaX(crypto.SHA3_384, p, sum[:]) {
		panic("openssl: SHA3_384 failed")
	}
	return
}

func SHA3_512(p []byte) (sum [64]byte) {
	if !shaX(crypto.SHA3_512, p, sum[:]) {
		panic("openssl: SHA3_512 failed")
	}
	return
}

// evpHash implements generic hash methods.
type evpHash struct {
	ctx C.GO_EVP_MD_CTX_PTR
	// ctx2 is used in evpHash.sum to avoid changing
	// the state of ctx. Having it here allows reusing the
	// same allocated object multiple times.
	ctx2      C.GO_EVP_MD_CTX_PTR
	size      int
	blockSize int
}

func newEvpHash(ch crypto.Hash, size, blockSize int) *evpHash {
	md := cryptoHashToMD(ch)
	if md == nil {
		panic("openssl: unsupported hash function: " + strconv.Itoa(int(ch)))
	}
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if C.go_openssl_EVP_DigestInit_ex(ctx, md, nil) != 1 {
		C.go_openssl_EVP_MD_CTX_free(ctx)
		panic(newOpenSSLError("EVP_DigestInit_ex"))
	}
	ctx2 := C.go_openssl_EVP_MD_CTX_new()
	h := &evpHash{
		ctx:       ctx,
		ctx2:      ctx2,
		size:      size,
		blockSize: blockSize,
	}
	runtime.SetFinalizer(h, (*evpHash).finalize)
	return h
}

func (h *evpHash) finalize() {
	C.go_openssl_EVP_MD_CTX_free(h.ctx)
	C.go_openssl_EVP_MD_CTX_free(h.ctx2)
}

func (h *evpHash) Reset() {
	// There is no need to reset h.ctx2 because it is always reset after
	// use in evpHash.sum.
	if C.go_openssl_EVP_DigestInit_ex(h.ctx, nil, nil) != 1 {
		panic(newOpenSSLError("EVP_DigestInit_ex"))
	}
	runtime.KeepAlive(h)
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) > 0 && C.go_openssl_EVP_DigestUpdate(h.ctx, unsafe.Pointer(&*addr(p)), C.size_t(len(p))) != 1 {
		panic(newOpenSSLError("EVP_DigestUpdate"))
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	if len(s) > 0 && C.go_openssl_EVP_DigestUpdate(h.ctx, unsafe.StringData(s), C.size_t(len(s))) == 0 {
		panic("openssl: EVP_DigestUpdate failed")
	}
	runtime.KeepAlive(h)
	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	if C.go_openssl_EVP_DigestUpdate(h.ctx, unsafe.Pointer(&c), 1) == 0 {
		panic("openssl: EVP_DigestUpdate failed")
	}
	runtime.KeepAlive(h)
	return nil
}

func (h *evpHash) Size() int {
	return h.size
}

func (h *evpHash) BlockSize() int {
	return h.blockSize
}

func (h *evpHash) sum(out []byte) {
	if C.go_sha_sum(h.ctx, h.ctx2, base(out)) != 1 {
		panic(newOpenSSLError("go_sha_sum"))
	}
	runtime.KeepAlive(h)
}

// shaState returns a pointer to the internal sha structure.
//
// The EVP_MD_CTX memory layout has changed in OpenSSL 3
// and the property holding the internal structure is no longer md_data but algctx.
func (h *evpHash) shaState() unsafe.Pointer {
	switch vMajor {
	case 1:
		// https://github.com/openssl/openssl/blob/0418e993c717a6863f206feaa40673a261de7395/crypto/evp/evp_local.h#L12.
		type mdCtx struct {
			_       [2]unsafe.Pointer
			_       C.ulong
			md_data unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(h.ctx)).md_data
	case 3:
		// https://github.com/openssl/openssl/blob/5675a5aaf6a2e489022bcfc18330dae9263e598e/crypto/evp/evp_local.h#L16.
		type mdCtx struct {
			_      [3]unsafe.Pointer
			_      C.ulong
			_      [3]unsafe.Pointer
			algctx unsafe.Pointer
		}
		return (*mdCtx)(unsafe.Pointer(h.ctx)).algctx
	default:
		panic(errUnsupportedVersion())
	}
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return &sha1Hash{
		evpHash: newEvpHash(crypto.SHA1, 20, 64),
	}
}

type sha1Hash struct {
	*evpHash
	out [20]byte
}

func (h *sha1Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
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

func (h *sha1Hash) MarshalBinary() ([]byte, error) {
	d := (*sha1State)(h.shaState())
	if d == nil {
		return nil, errors.New("crypto/sha1: can't retrieve hash state")
	}
	b := make([]byte, 0, sha1MarshaledSize)
	b = append(b, sha1Magic...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha1Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(sha1Magic) || string(b[:len(sha1Magic)]) != sha1Magic {
		return errors.New("crypto/sha1: invalid hash state identifier")
	}
	if len(b) != sha1MarshaledSize {
		return errors.New("crypto/sha1: invalid hash state size")
	}
	d := (*sha1State)(h.shaState())
	if d == nil {
		return errors.New("crypto/sha1: can't retrieve hash state")
	}
	b = b[len(sha1Magic):]
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

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	return &sha224Hash{
		evpHash: newEvpHash(crypto.SHA224, 224/8, 64),
	}
}

type sha224Hash struct {
	*evpHash
	out [224 / 8]byte
}

func (h *sha224Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return &sha256Hash{
		evpHash: newEvpHash(crypto.SHA256, 256/8, 64),
	}
}

type sha256Hash struct {
	*evpHash
	out [256 / 8]byte
}

func (h *sha256Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
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

func (h *sha224Hash) MarshalBinary() ([]byte, error) {
	d := (*sha256State)(h.shaState())
	if d == nil {
		return nil, errors.New("crypto/sha256: can't retrieve hash state")
	}
	b := make([]byte, 0, marshaledSize256)
	b = append(b, magic224...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha256Hash) MarshalBinary() ([]byte, error) {
	d := (*sha256State)(h.shaState())
	if d == nil {
		return nil, errors.New("crypto/sha256: can't retrieve hash state")
	}
	b := make([]byte, 0, marshaledSize256)
	b = append(b, magic256...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, uint64(d.nl)>>3|uint64(d.nh)<<29)
	return b, nil
}

func (h *sha224Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic224) || string(b[:len(magic224)]) != magic224 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256State)(h.shaState())
	if d == nil {
		return errors.New("crypto/sha256: can't retrieve hash state")
	}
	b = b[len(magic224):]
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

func (h *sha256Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic256) || string(b[:len(magic256)]) != magic256 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	d := (*sha256State)(h.shaState())
	if d == nil {
		return errors.New("crypto/sha256: can't retrieve hash state")
	}
	b = b[len(magic256):]
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

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return &sha384Hash{
		evpHash: newEvpHash(crypto.SHA384, 384/8, 128),
	}
}

type sha384Hash struct {
	*evpHash
	out [384 / 8]byte
}

func (h *sha384Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return &sha512Hash{
		evpHash: newEvpHash(crypto.SHA512, 512/8, 128),
	}
}

type sha512Hash struct {
	*evpHash
	out [512 / 8]byte
}

func (h *sha512Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
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

func (h *sha384Hash) MarshalBinary() ([]byte, error) {
	d := (*sha512State)(h.shaState())
	if d == nil {
		return nil, errors.New("crypto/sha512: can't retrieve hash state")
	}
	b := make([]byte, 0, marshaledSize512)
	b = append(b, magic384...)
	b = appendUint64(b, d.h[0])
	b = appendUint64(b, d.h[1])
	b = appendUint64(b, d.h[2])
	b = appendUint64(b, d.h[3])
	b = appendUint64(b, d.h[4])
	b = appendUint64(b, d.h[5])
	b = appendUint64(b, d.h[6])
	b = appendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha512Hash) MarshalBinary() ([]byte, error) {
	d := (*sha512State)(h.shaState())
	if d == nil {
		return nil, errors.New("crypto/sha512: can't retrieve hash state")
	}
	b := make([]byte, 0, marshaledSize512)
	b = append(b, magic512...)
	b = appendUint64(b, d.h[0])
	b = appendUint64(b, d.h[1])
	b = appendUint64(b, d.h[2])
	b = appendUint64(b, d.h[3])
	b = appendUint64(b, d.h[4])
	b = appendUint64(b, d.h[5])
	b = appendUint64(b, d.h[6])
	b = appendUint64(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.nl>>3|d.nh<<61)
	return b, nil
}

func (h *sha384Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic384)]) != magic384 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512State)(h.shaState())
	if d == nil {
		return errors.New("crypto/sha512: can't retrieve hash state")
	}
	b = b[len(magic512):]
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

func (h *sha512Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic512)]) != magic512 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	d := (*sha512State)(h.shaState())
	if d == nil {
		return errors.New("crypto/sha512: can't retrieve hash state")
	}
	b = b[len(magic512):]
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

// NewSHA3_224 returns a new SHA3-224 hash.
func NewSHA3_224() hash.Hash {
	return &sha3_224Hash{
		evpHash: newEvpHash(crypto.SHA3_224, 224/8, 64),
	}
}

type sha3_224Hash struct {
	*evpHash
	out [224 / 8]byte
}

func (h *sha3_224Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewSHA3_256 returns a new SHA3-256 hash.
func NewSHA3_256() hash.Hash {
	return &sha3_256Hash{
		evpHash: newEvpHash(crypto.SHA3_256, 256/8, 64),
	}
}

type sha3_256Hash struct {
	*evpHash
	out [256 / 8]byte
}

func (h *sha3_256Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewSHA3_384 returns a new SHA3-384 hash.
func NewSHA3_384() hash.Hash {
	return &sha3_384Hash{
		evpHash: newEvpHash(crypto.SHA3_384, 384/8, 128),
	}
}

type sha3_384Hash struct {
	*evpHash
	out [384 / 8]byte
}

func (h *sha3_384Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewSHA3_512 returns a new SHA3-512 hash.
func NewSHA3_512() hash.Hash {
	return &sha3_512Hash{
		evpHash: newEvpHash(crypto.SHA3_512, 512/8, 128),
	}
}

type sha3_512Hash struct {
	*evpHash
	out [512 / 8]byte
}

func (h *sha3_512Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
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
