//go:build !cmd_go_bootstrap && cgo

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

// #include "leak_check.h"
import "C"
import (
	"encoding/binary"
	"errors"
	"math/bits"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

var (
	// vMajor and vMinor hold the major/minor OpenSSL version.
	// It is only populated if Init has been called.
	vMajor, vMinor, vPatch uint
)

var (
	initOnce sync.Once
	initErr  error
)

var nativeEndian binary.ByteOrder

// CheckVersion checks if the OpenSSL version can be loaded
// and if the FIPS mode is enabled.
// This function can be called before Init.
func CheckVersion(version string) (exists, fips bool) {
	handle, _ := dlopen(version)
	if handle == nil {
		return false, false
	}
	defer dlclose(handle)
	enabled := ossl.Go_openssl_fips_enabled(handle)
	fips = enabled == 1
	// If go_openssl_fips_enabled returns -1, it means that all or some of the necessary
	// functions are not available. This can be due to the version of OpenSSL being too old,
	// too incompatible, or the shared library not being an OpenSSL library. In any case,
	// we shouldn't consider this library to be valid for our purposes.
	exists = enabled != -1
	return
}

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
	initOnce.Do(func() {
		buf := [2]byte{}
		*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

		switch buf {
		case [2]byte{0xCD, 0xAB}:
			nativeEndian = binary.LittleEndian
		case [2]byte{0xAB, 0xCD}:
			nativeEndian = binary.BigEndian
		default:
			panic("Could not determine native endianness.")
		}
		vMajor, vMinor, vPatch, initErr = opensslInit(file)
	})
	return initErr
}

func utoa(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}

func errUnsupportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + utoa(vMajor) + "." + utoa(vMinor) + "." + utoa(vPatch))
}

// checkMajorVersion panics if the current major version is not expected.
func checkMajorVersion(expected uint) {
	if vMajor != expected {
		panic("openssl: incorrect major version (" + strconv.Itoa(int(vMajor)) + "), expected " + strconv.Itoa(int(expected)))
	}
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	v := ossl.OpenSSL_version(0)
	return goString(v)
}

const (
	providerNameFips    = "fips\x00"
	providerNameDefault = "default\x00"
	propFIPS            = "fips=yes\x00"
	propNoFIPS          = "-fips\x00"

	algorithmSHA256 = "SHA2-256\x00"
)

// FIPS returns true if OpenSSL is running in FIPS mode and there is
// a provider available that supports FIPS. It returns false otherwise.
func FIPS() bool {
	switch vMajor {
	case 1:
		return ossl.FIPS_mode() == 1
	case 3:
		// Check if the default properties contain `fips=1`.
		if ossl.EVP_default_properties_is_fips_enabled(nil) != 1 {
			// Note that it is still possible that the provider used by default is FIPS-compliant,
			// but that wouldn't be a system or user requirement.
			return false
		}
		// Check if the SHA-256 algorithm is available. If it is, then we can be sure that there is a provider available that matches
		// the `fips=1` query. Most notably, this works for the common case of using the built-in FIPS provider.
		//
		// Note that this approach has a small chance of false negative if the FIPS provider doesn't provide the SHA-256 algorithm,
		// but that is highly unlikely because SHA-256 is one of the most common algorithms and fundamental to many cryptographic operations.
		// It also has a small chance of false positive if the FIPS provider implements the SHA-256 algorithm but not the other algorithms
		// used by the caller application, but that is also unlikely because the FIPS provider should provide all common algorithms.
		return proveSHA256(nil)
	default:
		panic(errUnsupportedVersion())
	}
}

// isProviderAvailable checks if the provider with the given name is available.
// This function is used in export_test.go, but must be defined here as test files can't access C functions.
func isProviderAvailable(name string) bool {
	if vMajor == 1 {
		return false
	}
	return ossl.OSSL_PROVIDER_available(nil, cStringData(name)) == 1
}

// SetFIPS enables or disables FIPS mode.
//
// For OpenSSL 3, if there is no provider available that supports FIPS mode,
// SetFIPS will try to load a built-in provider that supports FIPS mode.
func SetFIPS(enable bool) error {
	if FIPS() == enable {
		// Already in the desired state.
		return nil
	}
	var mode int32
	if enable {
		mode = 1
	} else {
		mode = 0
	}
	switch vMajor {
	case 1:
		return ossl.FIPS_mode_set(mode)
	case 3:
		var shaProps, provName string
		if enable {
			shaProps = propFIPS
			provName = providerNameFips
		} else {
			shaProps = propNoFIPS
			provName = providerNameDefault
		}
		if !proveSHA256(cStringData(shaProps)) {
			// There is no provider available that supports the desired FIPS mode.
			// Try to load the built-in provider associated with the given mode.
			if _, err := ossl.OSSL_PROVIDER_try_load(nil, cStringData(provName), 1); err != nil {
				// The built-in provider was not loaded successfully, we can't enable FIPS mode.
				ossl.ERR_clear_error()
				return errors.New("openssl: FIPS mode not supported by any provider")
			}
		}
		return ossl.EVP_default_properties_enable_fips(nil, mode)
	default:
		panic(errUnsupportedVersion())
	}
}

// proveSHA256 checks if the SHA-256 algorithm is available
// using the given properties.
func proveSHA256(props *byte) bool {
	md, err := ossl.EVP_MD_fetch(nil, cStringData(algorithmSHA256), props)
	if err != nil {
		ossl.ERR_clear_error()
		return false
	}
	ossl.EVP_MD_free(md)
	return true
}

// noescape hides a pointer from escape analysis. noescape is
// the identity function but escape analysis doesn't think the
// output depends on the input. noescape is inlined and currently
// compiles down to zero instructions.
// USE CAREFULLY!
//
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

var zero byte

// addr converts p to its base addr, including a noescape along the way.
// If p is nil, addr returns a non-nil pointer, so that the result can always
// be dereferenced.
//
//go:nosplit
func addr(p []byte) *byte {
	if len(p) == 0 {
		return &zero
	}
	return (*byte)(noescape(unsafe.Pointer(&p[0])))
}

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *byte {
	return unsafe.SliceData(b)
}

// stringData returns a pointer to the underlying bytes of s.
// If s is not empty it must end in a NUL byte.
// The returned pointer is valid for the lifetime of s.
// If s is empty, stringData returns nil.
func cStringData(s string) *byte {
	if len(s) == 0 {
		return nil
	}
	if s[len(s)-1] != 0 {
		panic("openssl: stringData not NUL-terminated")
	}
	for i := 0; i < len(s)-1; i++ {
		if s[i] == 0 {
			panic("openssl: string contains non-trailing NUL byte")
		}
	}
	return unsafe.StringData(s)
}

func newOpenSSLError(msg string) error {
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):")
	for {
		var (
			e    uint64
			file *byte
			line int32
		)
		switch vMajor {
		case 1:
			e = ossl.ERR_get_error_line(&file, &line)
		case 3:
			e = ossl.ERR_get_error_all(&file, &line, nil, nil, nil)
		default:
			panic(errUnsupportedVersion())
		}
		if e == 0 {
			break
		}
		b.WriteByte('\n')
		var buf [256]byte
		ossl.ERR_error_string_n(e, &buf[0], len(buf))
		b.WriteString(string(buf[:]) + "\n\t" + goString(file) + ":" + strconv.Itoa(int(line)))
	}
	return errors.New(b.String())
}

// goString converts a C null-terminated string to a Go string.
func goString(p *byte) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	n := 0
	for *(*byte)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}
	return string(unsafe.Slice(p, n))
}

var unknownFile = "<go code>\000"

// caller reports file and line number information about function invocations on
// the calling goroutine's stack, in a form suitable for passing to C code.
// The argument skip is the number of stack frames to ascend, with 0 identifying
// the caller of caller. The return values report the file name and line number
// within the file of the corresponding call. The returned file is a C string
// with static storage duration.
func caller(skip int) (file *byte, line int32) {
	_, f, l, ok := runtime.Caller(skip + 1)
	if !ok {
		f = unknownFile
	}
	// The underlying bytes of the file string are null-terminated rodata with
	// static lifetimes, so can be safely passed to C without worrying about
	// leaking memory or use-after-free.
	return (*byte)(noescape(unsafe.Pointer(unsafe.StringData(f)))), int32(l)
}

//go:linkname runtime_throw runtime.throw
func runtime_throw(string)

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
	file, line := caller(1)
	var p unsafe.Pointer
	if vMajor == 1 && vMinor == 0 {
		p = ossl.CRYPTO_malloc_legacy102(int32(n), file, line)
	} else {
		p = ossl.CRYPTO_malloc(n, file, line)
	}
	if p == nil {
		// Un-recover()-ably crash the program in the same manner as the
		// C.malloc() wrapper function.
		runtime_throw("openssl: CRYPTO_malloc failed")
	}
	return p
}

// cryptoFree frees an object allocated on the OpenSSL heap, which may be
// different from the heap which C.malloc allocates on. cryptoFree is equivalent
// to the OPENSSL_free macro.
func cryptoFree(p unsafe.Pointer) {
	if vMajor == 1 && vMinor == 0 {
		ossl.CRYPTO_free_legacy102(p)
		return
	}
	file, line := caller(1)
	ossl.CRYPTO_free(p, file, line)
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
	return (*byte)(unsafe.Pointer(&b[0]))
}

// bignum_st_1_0_2 is bignum_st (BIGNUM) memory layout in OpenSSL 1.0.2.
type bignum_st_1_0_2 struct {
	d     unsafe.Pointer // Pointer to an array of BN_ULONG bit chunks
	top   int32          // Index of last used d +1
	dmax  int32
	neg   int32
	flags int32
}

func bigToBN(x BigInt) ossl.BIGNUM_PTR {
	if len(x) == 0 {
		return nil
	}

	if vMajor == 1 && vMinor == 0 {
		// OpenSSL 1.0.x does not export bn_lebin2bn on all platforms,
		// so we have to emulate it.
		bn, err := ossl.BN_new()
		if err != nil {
			return nil
		}
		if _, err := ossl.BN_expand2(bn, int32(len(x))); err != nil {
			ossl.BN_free(bn)
			panic(err)
		}
		// The bytes of a BigInt are laid out in memory in the same order as a
		// BIGNUM, regardless of host endianness.
		bns := (*bignum_st_1_0_2)(unsafe.Pointer(bn))
		d := unsafe.Slice((*uint)(bns.d), len(x))
		bns.top = int32(copy(d, x))
		return bn
	}

	if nativeEndian == binary.BigEndian {
		z := make(BigInt, len(x))
		copy(z, x)
		z.byteSwap()
		x = z
	}
	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_lebin2bn regardless of host endianness.
	bn, _ := ossl.BN_lebin2bn(wbase(x), int32(len(x)*wordBytes), nil)
	return bn
}

func bnToBig(bn ossl.BIGNUM_PTR) BigInt {
	if bn == nil {
		return nil
	}

	if vMajor == 1 && vMinor == 0 {
		// OpenSSL 1.0.x does not export bn_bn2lebinpad on all platforms,
		// so we have to emulate it.
		bns := (*bignum_st_1_0_2)(unsafe.Pointer(bn))
		d := unsafe.Slice((*uint)(bns.d), bns.top)
		x := make(BigInt, len(d))
		copy(x, d)
		return x
	}

	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_bn2lebinpad regardless of host endianness.
	x := make(BigInt, ossl.BN_num_bits(bn))
	if _, err := ossl.BN_bn2lebinpad(bn, wbase(x), int32(len(x)*wordBytes)); err != nil {
		panic("openssl: bignum conversion failed")
	}
	if nativeEndian == binary.BigEndian {
		x.byteSwap()
	}
	return x
}

func bnNumBytes(bn ossl.BIGNUM_PTR) int32 {
	return (ossl.BN_num_bits(bn) + 7) / 8
}

// bnToBinPad converts the absolute value of bn into big-endian form and stores
// it at to, padding with zeroes if necessary. If len(to) is not large enough to
// hold the result, an error is returned.
func bnToBinPad(bn ossl.BIGNUM_PTR, to []byte) error {
	if vMajor == 1 && vMinor == 0 {
		// OpenSSL 1.0.x does not export bn_bn2binpad on all platforms,
		// so we have to emulate it.
		n := bnNumBytes(bn)
		pad := int32(len(to)) - n
		if pad < 0 {
			return errors.New("openssl: destination buffer too small")
		}
		for i := range pad {
			to[i] = 0
		}
		if ossl.BN_bn2bin(bn, base(to[pad:])) != n {
			return errors.New("openssl: BN_bn2bin short write")
		}
		return nil
	}

	if _, err := ossl.BN_bn2binpad(bn, base(to), int32(len(to))); err != nil {
		return err
	}
	return nil
}

func CheckLeaks() {
	C.go_openssl_do_leak_check()
}

// versionAtOrAbove returns true when
// (vMajor, vMinor, vPatch) >= (major, minor, patch),
// compared lexicographically.
func versionAtOrAbove(major, minor, patch uint) bool {
	return vMajor > major || (vMajor == major && vMinor > minor) || (vMajor == major && vMinor == minor && vPatch >= patch)
}
