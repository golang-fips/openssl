//go:build !cmd_go_bootstrap && (cgo || goexperiment.ms_nocgo_opensslcrypto)

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

import (
	"errors"
	"math/bits"
	"strconv"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
	"github.com/golang-fips/openssl/v2/osslsetup"
)

var (
	// vMajor and vMinor hold the major/minor OpenSSL version.
	// It is only populated if Init has been called.
	vMajor, vMinor, vPatch int
)

// CheckVersion checks if the OpenSSL version can be loaded
// and if the FIPS mode is enabled.
// This function can be called before Init.
// All OpenSSL functions used in here should be tagged with "init_1" or "init_3" in shims.h.
func CheckVersion(version string) (exists, fips bool) {
	return osslsetup.CheckVersion(version)
}

var isBigEndian bool

// Init loads and initializes OpenSSL from the shared library at path.
// It must be called before any other OpenSSL call, except CheckVersion.
//
// Only the first call to Init is effective.
// Subsequent calls will return the same error result as the one from the first call.
//
// The file is passed to dlopen() verbatim to load the OpenSSL shared library.
// For example, `file=libcrypto.so.1.1.1k-fips` makes Init look for the shared
// library libcrypto.so.1.1.1k-fips.
func Init(file string) error {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		isBigEndian = false
	case [2]byte{0xAB, 0xCD}:
		isBigEndian = true
	default:
		panic("Could not determine native endianness.")
	}
	if err := osslsetup.Init(file); err != nil {
		return err
	}
	vMajor, vMinor, vPatch = osslsetup.Version()
	return nil
}

func utoa(n int) string {
	return strconv.FormatUint(uint64(n), 10)
}

func errUnsupportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + utoa(vMajor) + "." + utoa(vMinor) + "." + utoa(vPatch))
}

// checkMajorVersion panics if the current major version is not expected.
func checkMajorVersion(expected int) {
	if vMajor != expected {
		panic("openssl: incorrect major version (" + strconv.Itoa(vMajor) + "), expected " + strconv.Itoa(expected))
	}
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

// VersionText returns the version text of the OpenSSL currently loaded.
//
//go:fix inline
func VersionText() string {
	return osslsetup.VersionText()
}

// FIPS returns true if OpenSSL is running in FIPS mode and there is
// a provider available that supports FIPS. It returns false otherwise.
// All OpenSSL functions used in here should be tagged with "init_1" or "init_3" in shims.h.
//
//go:fix inline
func FIPS() bool {
	return osslsetup.FIPS()
}

// FIPSCapable returns true if the provider used by default matches the `fips=yes` query.
// See [osslsetup.FIPSCapable] for details.
//
//go:fix inline
func FIPSCapable() bool {
	return osslsetup.FIPSCapable()
}

// SetFIPS enables or disables FIPS mode.
//
// For OpenSSL 3, if there is no provider available that supports FIPS mode,
// SetFIPS will try to load a built-in provider that supports FIPS mode.
//
//go:fix inline
func SetFIPS(enable bool) error {
	return osslsetup.SetFIPS(enable)
}

var zero byte

// baseNeverEmpty returns the address of the underlying array in b.
// If b has zero length, it returns a pointer to a zero byte.
func baseNeverEmpty(b []byte) *byte {
	if len(b) == 0 {
		return &zero
	}
	return unsafe.SliceData(b)
}

// pbase returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func pbase(b []byte) unsafe.Pointer {
	return unsafe.Pointer(base(b))
}

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return unsafe.SliceData(b)
}

//go:linkname throw runtime.throw
func throw(string)

// cryptoMalloc allocates n bytes of memory on the OpenSSL heap, which may be
// different from the heap which C.malloc allocates on. The allocated object
// must be freed using cryptoFree. cryptoMalloc is equivalent to the
// OPENSSL_malloc macro.
//
// Like C.malloc, this function is guaranteed to never return nil. If OpenSSL's
// malloc indicates out of memory, it crashes the program.
//
// Only objects which the OpenSSL library will take ownership of (i.e. will be
// freed by OPENSSL_free / CRYPTO_free) need to be allocated on the OpenSSL
// heap.
func cryptoMalloc(n int) unsafe.Pointer {
	p, _ := ossl.CRYPTO_malloc(n, nil, 0)
	if p == nil {
		// Un-recover()-ably crash the program in the same manner as the
		// C.malloc() wrapper function.
		throw("openssl: CRYPTO_malloc failed")
	}
	return p
}

// cryptoFree frees an object allocated on the OpenSSL heap, which may be
// different from the heap which C.malloc allocates on. cryptoFree is equivalent
// to the OPENSSL_free macro.
func cryptoFree(p unsafe.Pointer) {
	ossl.CRYPTO_free(p, nil, 0)
}

const wordBytes = bits.UintSize / 8

// Reverse each limb of z.
func (z BigInt) byteSwap() {
	for i, d := range z {
		var n uint = 0
		for j := range wordBytes {
			n |= uint(byte(d)) << (8 * (wordBytes - j - 1))
			d >>= 8
		}
		z[i] = n
	}
}

func wbase(b BigInt) *byte {
	if len(b) == 0 {
		return nil
	}
	return (*byte)(unsafe.Pointer(unsafe.SliceData(b)))
}

func bigToBN(x BigInt) (ossl.BIGNUM_PTR, error) {
	if len(x) == 0 {
		return nil, nil
	}
	if isBigEndian {
		z := make(BigInt, len(x))
		copy(z, x)
		z.byteSwap()
		x = z
	}
	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_lebin2bn regardless of host endianness.
	bn, err := ossl.BN_lebin2bn(wbase(x), int32(len(x)*wordBytes), nil)
	if err != nil {
		return nil, err
	}
	return bn, nil
}

func bnToBig(bn ossl.BIGNUM_PTR) BigInt {
	if bn == nil {
		return nil
	}

	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_bn2lebinpad regardless of host endianness.
	x := make(BigInt, ossl.BN_num_bits(bn))
	if _, err := ossl.BN_bn2lebinpad(bn, wbase(x), int32(len(x)*wordBytes)); err != nil {
		panic(err)
	}
	if isBigEndian {
		x.byteSwap()
	}
	return x
}

// bnToBinPad converts the absolute value of bn into big-endian form and stores
// it at to, padding with zeroes if necessary. If len(to) is not large enough to
// hold the result, an error is returned.
func bnToBinPad(bn ossl.BIGNUM_PTR, to []byte) error {
	_, err := ossl.BN_bn2binpad(bn, base(to), int32(len(to)))
	return err
}

// versionAtOrAbove returns true when
// (vMajor, vMinor, vPatch) >= (major, minor, patch),
// compared lexicographically.
func versionAtOrAbove(major, minor, patch int) bool {
	return vMajor > major || (vMajor == major && vMinor > minor) || (vMajor == major && vMinor == minor && vPatch >= patch)
}

func bigEndianUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}
