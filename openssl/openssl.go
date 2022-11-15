//go:build linux && !android
// +build linux,!android

// Package openssl provides access to OpenSSL cryptographic functions.
package openssl

// #include "goopenssl.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"encoding/binary"
	"errors"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

var (
	// vMajor and vMinor hold the major/minor OpenSSL version.
	// It is only populated if Init has been called.
	vMajor, vMinor int
)

var (
	initOnce sync.Once
	initErr  error
)

var nativeEndian binary.ByteOrder

// Init loads and initializes OpenSSL.
// It must be called before any other OpenSSL call.
//
// Only the first call to Init is effective,
// subsequent calls will return the same error result as the one from the first call.
//
// If version is not empty, its value will be appended to the OpenSSL shared library name
// as a version suffix when calling dlopen. For example, `version=1.1.1k-fips`
// makes Init look for the shared library libcrypto.so.1.1.1k-fips.
// If version is empty, Init will try to load the OpenSSL shared library
// using a list of supported and well-known version suffixes, going from higher to lower versions.
func Init(version string) error {
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
		vMajor, vMinor, initErr = opensslInit(version)
	})
	return initErr
}

func errUnsupportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + strconv.Itoa(vMajor) + "." + strconv.Itoa(vMinor))
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	return C.GoString(C.go_openssl_OpenSSL_version(0))
}

var (
	providerNameFips    = C.CString("fips")
	providerNameDefault = C.CString("default")
	propFipsYes         = C.CString("fips=yes")
	propFipsNo          = C.CString("fips=no")
	algProve            = C.CString("SHA2-256")
)

// providerAvailable looks through provider's digests
// checking if there is any that matches the props query.
func providerAvailable(props *C.char) bool {
	C.go_openssl_ERR_set_mark()
	defer C.go_openssl_ERR_pop_to_mark()
	md := C.go_openssl_EVP_MD_fetch(nil, algProve, props)
	if md == nil {
		return false
	}
	C.go_openssl_EVP_MD_free(md)
	return true
}

// FIPS returns true if OpenSSL is running in FIPS mode, else returns false.
func FIPS() bool {
	switch vMajor {
	case 1:
		return C.go_openssl_FIPS_mode() == 1
	case 3:
		// If FIPS is not enabled via default properties, then we are sure FIPS is not used.
		if C.go_openssl_EVP_default_properties_is_fips_enabled(nil) == 0 {
			return false
		}
		// EVP_default_properties_is_fips_enabled can return true even if the FIPS provider isn't loaded,
		// it is only based on the default properties.
		// We can be sure that the FIPS provider is available if we can fetch an algorithm, e.g., SHA2-256,
		// explictly setting `fips=yes`.
		return providerAvailable(propFipsYes)
	default:
		panic(errUnsupportedVersion())
	}
}

// SetFIPS enables or disables FIPS mode.
//
// It implements the following provider fallback logic for OpenSSL 3:
//   - The "fips" provider is loaded if enabled=true and no loaded provider matches "fips=yes".
//   - The "default" provider is loaded if enabled=false and no loaded provider matches "fips=no".
//
// This logic allows advanced users to define their own providers that match "fips=yes" and "fips=no" using the OpenSSL config file.
func SetFIPS(enabled bool) error {
	switch vMajor {
	case 1:
		var mode C.int
		if enabled {
			mode = C.int(1)
		} else {
			mode = C.int(0)
		}
		if C.go_openssl_FIPS_mode_set(mode) != 1 {
			return newOpenSSLError("FIPS_mode_set")
		}
		return nil
	case 3:
		var props, provName *C.char
		if enabled {
			props = propFipsYes
			provName = providerNameFips
		} else {
			props = propFipsNo
			provName = providerNameDefault
		}
		// Check if there is any provider that matches props.
		if !providerAvailable(props) {
			// If not, fallback to provName provider.
			if C.go_openssl_OSSL_PROVIDER_load(nil, provName) == nil {
				return newOpenSSLError("OSSL_PROVIDER_try_load")
			}
			// Make sure we now have a provider available.
			if !providerAvailable(props) {
				return fail("SetFIPS(" + strconv.FormatBool(enabled) + ") not supported")
			}
		}
		if C.go_openssl_EVP_set_default_properties(nil, props) != 1 {
			return newOpenSSLError("EVP_set_default_properties")
		}
		return nil
	default:
		panic(errUnsupportedVersion())
	}
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

const wordBytes = bits.UintSize / 8

// Reverse each limb of z.
func (z BigInt) byteSwap() {
	for i, d := range z {
		var n uint = 0
		for j := 0; j < wordBytes; j++ {
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
