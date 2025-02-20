//go:build !cmd_go_bootstrap

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

// #include "goopenssl.h"
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
	enabled := C.go_openssl_fips_enabled(handle)
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
	return C.GoString(C.go_openssl_OpenSSL_version(0))
}

// FIPS returns true if OpenSSL is running in FIPS mode and there is
// a provider available that supports FIPS. It returns false otherwise.
func FIPS() bool {
	switch vMajor {
	case 1:
		return C.go_openssl_FIPS_mode() == 1
	case 3:
		// Check if the default properties contain `fips=1`.
		if C.go_openssl_EVP_default_properties_is_fips_enabled(nil) != 1 {
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
		return proveSHA256("")
	default:
		panic(errUnsupportedVersion())
	}
}

// FIPSCapable returns true if the provider used by default matches the `fips=yes` query.
// It is useful for checking whether OpenSSL is capable of running in FIPS mode regardless
// of whether FIPS mode is explicitly enabled. For example, Azure Linux 3 doesn't set the
// `fips=yes` query in the default properties, but sets the default provider to be SCOSSL,
// which is FIPS-capable.
//
// Considerations:
//   - Multiple calls to FIPSCapable can return different values if [SetFIPS] is called in between.
//   - Can return true even if [FIPS] returns false, because [FIPS] also checks whether
//     the default properties contain `fips=yes`.
//   - When using OpenSSL 3, will always return true if [FIPS] returns true.
//   - When using OpenSSL 1, Will always return the same value as [FIPS].
//   - OpenSSL 3 doesn't provide a way to know if a provider is FIPS-capable. This function uses
//     some heuristics that should be treated as an implementation detail that may change in the future.
func FIPSCapable() bool {
	if FIPS() {
		return true
	}
	if vMajor == 3 {
		// Load the provider with and without the `fips=yes` query.
		// If the providers are the same, then the default provider is FIPS-capable.
		provFIPS := sha256Provider(_ProviderNameFips)
		if provFIPS == nil {
			return false
		}
		provDefault := sha256Provider("")
		return provFIPS == provDefault
	}
	return false
}

// isProviderAvailable checks if the provider with the given name is available.
// This function is used in export_test.go, but must be defined here as test files can't access C functions.
func isProviderAvailable(name string) bool {
	if vMajor == 1 {
		return false
	}
	providerName := C.CString(name)
	defer C.free(unsafe.Pointer(providerName))
	return C.go_openssl_OSSL_PROVIDER_available(nil, providerName) == 1
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
	var mode C.int
	if enable {
		mode = C.int(1)
	} else {
		mode = C.int(0)
	}
	switch vMajor {
	case 1:
		if C.go_openssl_FIPS_mode_set(mode) != 1 {
			return newOpenSSLError("FIPS_mode_set")
		}
		return nil
	case 3:
		var shaProps, provName cString
		if enable {
			shaProps = _PropFIPSYes
			provName = _ProviderNameFips
		} else {
			shaProps = _PropFIPSNo
			provName = _ProviderNameDefault
		}
		if !proveSHA256(shaProps) {
			// There is no provider available that supports the desired FIPS mode.
			// Try to load the built-in provider associated with the given mode.
			if C.go_openssl_OSSL_PROVIDER_try_load(nil, provName.ptr(), 1) == nil {
				// The built-in provider was not loaded successfully, we can't enable FIPS mode.
				C.go_openssl_ERR_clear_error()
				return errors.New("openssl: FIPS mode not supported by any provider")
			}
		}
		if C.go_openssl_EVP_default_properties_enable_fips(nil, mode) != 1 {
			return newOpenSSLError("EVP_default_properties_enable_fips")
		}
		return nil
	default:
		panic(errUnsupportedVersion())
	}
}

// sha256Provider returns the provider for the SHA-256 algorithm
// using the given properties.
func sha256Provider(props cString) C.GO_OSSL_PROVIDER_PTR {
	md := C.go_openssl_EVP_MD_fetch(nil, _DigestNameSHA2_256.ptr(), props.ptr())
	if md == nil {
		C.go_openssl_ERR_clear_error()
		return nil
	}
	defer C.go_openssl_EVP_MD_free(md)
	return C.go_openssl_EVP_MD_get0_provider(md)
}

// proveSHA256 checks if the SHA-256 algorithm is available
// using the given properties.
func proveSHA256(props cString) bool {
	return sha256Provider(props) != nil
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
func base(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func sbase(b []byte) *C.char {
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(&b[0]))
}

func newOpenSSLError(msg string) error {
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):")
	for {
		var (
			e    C.ulong
			file *C.char
			line C.int
		)
		switch vMajor {
		case 1:
			e = C.go_openssl_ERR_get_error_line(&file, &line)
		case 3:
			e = C.go_openssl_ERR_get_error_all(&file, &line, nil, nil, nil)
		default:
			panic(errUnsupportedVersion())
		}
		if e == 0 {
			break
		}
		b.WriteByte('\n')
		var buf [256]byte
		C.go_openssl_ERR_error_string_n(e, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		b.WriteString(string(buf[:]) + "\n\t" + C.GoString(file) + ":" + strconv.Itoa(int(line)))
	}
	return errors.New(b.String())
}

var unknownFile = "<go code>\000"

// caller reports file and line number information about function invocations on
// the calling goroutine's stack, in a form suitable for passing to C code.
// The argument skip is the number of stack frames to ascend, with 0 identifying
// the caller of caller. The return values report the file name and line number
// within the file of the corresponding call. The returned file is a C string
// with static storage duration.
func caller(skip int) (file *C.char, line C.int) {
	_, f, l, ok := runtime.Caller(skip + 1)
	if !ok {
		f = unknownFile
	}
	// The underlying bytes of the file string are null-terminated rodata with
	// static lifetimes, so can be safely passed to C without worrying about
	// leaking memory or use-after-free.
	return (*C.char)(noescape(unsafe.Pointer(unsafe.StringData(f)))), C.int(l)
}

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
	p := C.go_openssl_CRYPTO_malloc(C.size_t(n), file, line)
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
	file, line := caller(1)
	C.go_openssl_CRYPTO_free(p, file, line)
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

func wbase(b BigInt) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func bigToBN(x BigInt) C.GO_BIGNUM_PTR {
	if len(x) == 0 {
		return nil
	}
	if nativeEndian == binary.BigEndian {
		z := make(BigInt, len(x))
		copy(z, x)
		z.byteSwap()
		x = z
	}
	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_lebin2bn regardless of host endianness.
	return C.go_openssl_BN_lebin2bn(wbase(x), C.int(len(x)*wordBytes), nil)
}

func bnToBig(bn C.GO_BIGNUM_PTR) BigInt {
	if bn == nil {
		return nil
	}

	// Limbs are always ordered in LSB first, so we can safely apply
	// BN_bn2lebinpad regardless of host endianness.
	x := make(BigInt, C.go_openssl_BN_num_bits(bn))
	if C.go_openssl_BN_bn2lebinpad(bn, wbase(x), C.int(len(x)*wordBytes)) == 0 {
		panic("openssl: bignum conversion failed")
	}
	if nativeEndian == binary.BigEndian {
		x.byteSwap()
	}
	return x
}

// bnToBinPad converts the absolute value of bn into big-endian form and stores
// it at to, padding with zeroes if necessary. If len(to) is not large enough to
// hold the result, an error is returned.
func bnToBinPad(bn C.GO_BIGNUM_PTR, to []byte) error {
	if C.go_openssl_BN_bn2binpad(bn, base(to), C.int(len(to))) < 0 {
		return newOpenSSLError("BN_bn2binpad")
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
