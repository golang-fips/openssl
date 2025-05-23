//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"strconv"
	"sync"
	"unsafe"
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

	marshaledSizeMD5 = len(magicMD5) + 4*4 + 64 + 8
	marshaledSize1   = len(magic1) + 5*4 + 64 + 8
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8
)

// maxHashSize is the size of SHA52 and SHA3_512, the largest hashes we support.
const maxHashSize = 64

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

func hashOneShot(ch crypto.Hash, p []byte, sum []byte) bool {
	return C.go_openssl_EVP_Digest(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), (*C.uchar)(unsafe.Pointer(&*addr(sum))), nil, cryptoHashToMD(ch), nil) != 0
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

// SupportsHash returns true if a hash.Hash implementation is supported for h.
func SupportsHash(h crypto.Hash) bool {
	return cryptoHashToMD(h) != nil
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

// provider is an identifier for a known provider.
type provider uint8

const (
	providerNone provider = iota
	providerOSSLDefault
	providerOSSLFIPS
	providerSymCrypt
)

var mdProviderCache sync.Map

// mdProvider returns the provider for the given hash.
func mdProvider(ch crypto.Hash) provider {
	if vMajor == 1 {
		return providerOSSLDefault
	}
	if v, ok := mdProviderCache.Load(ch); ok {
		return v.(provider)
	}
	md := cryptoHashToMD(ch)
	if md == nil {
		return providerNone
	}
	prov := C.go_openssl_EVP_MD_get0_provider(md)
	if prov == nil {
		return providerNone
	}
	cname := C.go_openssl_OSSL_PROVIDER_get0_name(prov)
	if cname == nil {
		return providerNone
	}
	var provider provider
	switch C.GoString(cname) {
	case "default":
		provider = providerOSSLDefault
	case "fips":
		provider = providerOSSLFIPS
	case "symcryptprovider":
		provider = providerSymCrypt
	}
	mdProviderCache.Store(ch, provider)
	return provider
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

	ch crypto.Hash
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

		ch: ch,
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
	if len(s) > 0 && C.go_openssl_EVP_DigestUpdate(h.ctx, unsafe.Pointer(unsafe.StringData(s)), C.size_t(len(s))) == 0 {
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
	if C.go_hash_sum(h.ctx, h.ctx2, base(out)) != 1 {
		panic(newOpenSSLError("go_hash_sum"))
	}
	runtime.KeepAlive(h)
}

// clone returns a new evpHash object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *evpHash) clone() (*evpHash, error) {
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return nil, newOpenSSLError("EVP_MD_CTX_new")
	}
	if C.go_openssl_EVP_MD_CTX_copy_ex(ctx, h.ctx) != 1 {
		C.go_openssl_EVP_MD_CTX_free(ctx)
		return nil, newOpenSSLError("EVP_MD_CTX_copy_ex")
	}
	ctx2 := C.go_openssl_EVP_MD_CTX_new()
	if ctx2 == nil {
		C.go_openssl_EVP_MD_CTX_free(ctx)
		return nil, newOpenSSLError("EVP_MD_CTX_new")
	}
	cloned := &evpHash{
		ctx:       ctx,
		ctx2:      ctx2,
		size:      h.size,
		blockSize: h.blockSize,
		ch:        h.ch,
	}
	runtime.SetFinalizer(cloned, (*evpHash).finalize)
	return cloned, nil
}

var testNotMarshalable bool // Used in tests.

var errHashNotMarshallable = errors.New("openssl: hash state is not marshallable")

func (d *evpHash) MarshalBinary() ([]byte, error) {
	defer runtime.KeepAlive(d)
	buf := make([]byte, 0, marshaledSize512) // stack allocate the buffer by setting the max size we support
	magic, _ := cryptoHashEncodingInfo(d.ch)
	if magic == "" || testNotMarshalable {
		return nil, errHashNotMarshallable
	}
	switch mdProvider(d.ch) {
	case providerOSSLDefault, providerOSSLFIPS:
		return osslHashAppendBinary(d.ctx, d.ch, magic, buf)
	case providerSymCrypt:
		return symCryptHashAppendBinary(d.ctx, d.ch, magic, buf)
	default:
		return nil, errHashNotMarshallable
	}
}

func (d *evpHash) UnmarshalBinary(b []byte) error {
	defer runtime.KeepAlive(d)
	magic, size := cryptoHashEncodingInfo(d.ch)
	if magic == "" || testNotMarshalable {
		return errHashNotMarshallable
	}
	if len(b) < len(magic) || string(b[:len(magic)]) != string(magic[:]) {
		return errors.New("openssl: invalid hash state identifier")
	}
	if len(b) != size {
		return errors.New("openssl: invalid hash state size")
	}
	switch mdProvider(d.ch) {
	case providerOSSLDefault, providerOSSLFIPS:
		return osslHashUnmarshalBinary(d.ctx, d.ch, magic, b)
	case providerSymCrypt:
		return symCryptHashUnmarshalBinary(d.ctx, d.ch, magic, b)
	default:
		return errHashNotMarshallable
	}
}

func cryptoHashEncodingInfo(ch crypto.Hash) (magic string, size int) {
	switch ch {
	case crypto.MD5:
		return magicMD5, marshaledSizeMD5
	case crypto.SHA1:
		return magic1, marshaledSize1
	case crypto.SHA224:
		return magic224, marshaledSize256
	case crypto.SHA256:
		return magic256, marshaledSize256
	case crypto.SHA384:
		return magic384, marshaledSize512
	case crypto.SHA512_224:
		return magic512_224, marshaledSize512
	case crypto.SHA512_256:
		return magic512_256, marshaledSize512
	case crypto.SHA512:
		return magic512, marshaledSize512
	default:
		return "", 0
	}
}

// NewMD4 returns a new MD4 hash.
// The returned hash doesn't implement encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler.
func NewMD4() hash.Hash {
	return &md4Hash{
		evpHash: newEvpHash(crypto.MD4, 16, 64),
	}
}

type md4Hash struct {
	*evpHash
	out [16]byte
}

func (h *md4Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
}

// NewMD5 returns a new MD5 hash.
func NewMD5() hash.Hash {
	return &md5Hash{
		evpHash: newEvpHash(crypto.MD5, 16, 64),
	}
}

type md5Hash struct {
	*evpHash
	out [16]byte
}

func (h *md5Hash) Sum(in []byte) []byte {
	h.sum(h.out[:])
	return append(in, h.out[:]...)
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

// Clone returns a new [hash.Hash] object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *sha256Hash) Clone() (hash.Hash, error) {
	c, err := h.clone()
	if err != nil {
		return nil, err
	}
	return &sha256Hash{evpHash: c}, nil
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

// Clone returns a new [hash.Hash] object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *sha384Hash) Clone() (hash.Hash, error) {
	c, err := h.clone()
	if err != nil {
		return nil, err
	}
	return &sha384Hash{evpHash: c}, nil
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

// Clone returns a new [hash.Hash] object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *sha512Hash) Clone() (hash.Hash, error) {
	c, err := h.clone()
	if err != nil {
		return nil, err
	}
	return &sha512Hash{evpHash: c}, nil
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
