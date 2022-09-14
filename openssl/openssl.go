// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

/*
#cgo LDFLAGS: -ldl

#include "goopenssl.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"runtime"
	"unsafe"
)

const (
	fipsOn  = C.int(1)
	fipsOff = C.int(0)
)

const GoStrictFipsEnv = "GOLANG_STRICT_FIPS"

const (
	OPENSSL_VERSION_1_1_0 = uint64(C.ulong(0x10100000))
	OPENSSL_VERSION_3_0_0 = uint64(C.ulong(0x30000000))
)

// Enabled controls whether FIPS crypto is enabled.
var enabled = false

// When this variable is true, the go crypto API will panic when a caller
// tries to use the API in a non-compliant manner.  When this is false, the
// go crypto API will allow existing go crypto APIs to be used even
// if they aren't FIPS compliant.  However, all the underlying crypto operations
// will still be done by OpenSSL.
var strictFIPS = false

func init() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Check if we can `dlopen` OpenSSL
	if C._goboringcrypto_DLOPEN_OPENSSL() == C.NULL {
		return
	}

	// Initialize the OpenSSL library.
	C._goboringcrypto_OPENSSL_setup()

	// Check to see if the system is running in FIPS mode, if so
	// enable "boring" mode to call into OpenSSL for FIPS compliance.
	if fipsModeEnabled() {
		enableBoringFIPSMode()
	}
}

func openSSLVersion() uint64 {
	return uint64(C._goboringcrypto_internal_OPENSSL_VERSION_NUMBER())
}

func enableBoringFIPSMode() {
	enabled = true

	if os.Getenv(GoStrictFipsEnv) == "1" {
		strictFIPS = true
	}

	if C._goboringcrypto_OPENSSL_thread_setup() != 1 {
		panic("boringcrypto: OpenSSL thread setup failed")
	}
}

func fipsModeEnabled() bool {
	// Due to the way providers work in openssl 3, the FIPS methods are not
	// necessarily going to be available for us to load based on the GOLANG_FIPS
	// environment variable alone. For now, we must rely on the config to tell
	// us if the provider is configured and active.
	fipsConfigured := C._goboringcrypto_FIPS_mode() == fipsOn
	openSSLVersion := openSSLVersion()
	if openSSLVersion >= OPENSSL_VERSION_3_0_0 {
		if !fipsConfigured && os.Getenv("GOLANG_FIPS") == "1" {
			panic("GOLANG_FIPS=1 specified but OpenSSL FIPS provider is not configured")
		}
		return fipsConfigured

	} else {
		return os.Getenv("GOLANG_FIPS") == "1" || fipsConfigured
	}
}

var randstub bool

func RandStubbed() bool {
	return randstub
}

func StubOpenSSLRand() {
	if !randstub {
		randstub = true
		C._goboringcrypto_stub_openssl_rand()
	}
}

func RestoreOpenSSLRand() {
	if randstub {
		randstub = false
		C._goboringcrypto_restore_openssl_rand()
	}
}

func hasSuffix(s, t string) bool {
	return len(s) > len(t) && s[len(s)-len(t):] == t
}

func PanicIfStrictFIPS(msg string) {
	if IsStrictFips() {
		panic(msg)
	}
}

func IsStrictFips() bool {
	return os.Getenv(GoStrictFipsEnv) == "1" || strictFIPS
}

func NewOpenSSLError(msg string) error {
	var e C.ulong
	message := fmt.Sprintf("\n%v\nopenssl error(s):", msg)
	for {
		var buf [256]C.char
		var file, fnc, data *C.char
		var line, flags C.int
		e = C._goboringcrypto_internal_ERR_get_error_all(&file, &line, &fnc, &data, &flags)
		if e == 0 {
			break
		}

		C._goboringcrypto_internal_ERR_error_string_n(e, (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		message = fmt.Sprintf(
			"%v\nfile: %v\nline: %v\nfunction: %v\nflags: %v\nerror string: %s\n",
			message, C.GoString(file), line, C.GoString(fnc), flags, C.GoString(&(buf[0])))

	}
	return errors.New(message)
}

// Unreachable marks code that should be unreachable
// when FIPS mode. It panics only when
// the system is in FIPS mode.
func Unreachable() {
	if Enabled() {
		panic("openssl: invalid code execution")
	}
}

// UnreachableExceptTests marks code that should be unreachable
// when FIPS mode is active. It panics only when the system is in FIPS mode
// and not executing under tests.
func UnreachableExceptTests() {
	name := os.Args[0]
	if Enabled() && !ExecutingTest() {
		println("openssl: unexpected code execution in", name)
		panic("openssl: invalid code execution")
	}
}

// ExecutingTest returns a boolean indicating if we're
// executing under a test binary or not.
func ExecutingTest() bool {
	name := os.Args[0]
	return hasSuffix(name, "_test") || hasSuffix(name, ".test")
}

type fail string

func (e fail) Error() string { return "boringcrypto: " + string(e) + " failed" }

func wbase(b BigInt) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

const wordBytes = bits.UintSize / 8

func bigToBN(x BigInt) *C.GO_BIGNUM {
	return C._goboringcrypto_BN_lebin2bn(wbase(x), C.size_t(len(x)*wordBytes), nil)
}

func bnToBig(bn *C.GO_BIGNUM) BigInt {
	x := make(BigInt, (C._goboringcrypto_BN_num_bytes(bn)+wordBytes-1)/wordBytes)
	if C._goboringcrypto_BN_bn2lebinpad(bn, wbase(x), C.size_t(len(x)*wordBytes)) == 0 {
		panic("boringcrypto: bignum conversion failed")
	}
	return x
}

func bigToBn(bnp **C.GO_BIGNUM, b BigInt) bool {
	if *bnp != nil {
		C._goboringcrypto_BN_free(*bnp)
		*bnp = nil
	}
	if b == nil {
		return true
	}
	bn := bigToBN(b)
	if bn == nil {
		return false
	}
	*bnp = bn
	return true
}

// noescape hides a pointer from escape analysis.  noescape is
// the identity function but escape analysis doesn't think the
// output depends on the input.  noescape is inlined and currently
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
