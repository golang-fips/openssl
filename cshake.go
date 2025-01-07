//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"runtime"
	"strconv"
	"sync"
	"unsafe"
)

func shakeOneShot(size int, p []byte, sum []byte) bool {
	return C.go_openssl_EVP_Digest(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), (*C.uchar)(unsafe.Pointer(&*addr(sum))), nil, loadShake(size).md, nil) != 0
}

// SumSHAKE128 applies the SHAKE128 extendable output function to data and
// returns an output of the given length in bytes.
func SumSHAKE128(data []byte, length int) []byte {
	out := make([]byte, length)
	if !shakeOneShot(128, data, out[:]) {
		panic("openssl: SumSHAKE128 failed")
	}
	return out
}

// SumSHAKE256 applies the SHAKE256 extendable output function to data and
// returns an output of the given length in bytes.
func SumSHAKE256(data []byte, length int) []byte {
	out := make([]byte, length)
	if !shakeOneShot(256, data, out[:]) {
		panic("openssl: SumSHAKE256 failed")
	}
	return out
}

// SupportsSHAKE128 returns true if the SHAKE128 extendable output function is
// supported.
func SupportsSHAKE128() bool {
	return supportsSHAKE(128)
}

// SupportsSHAKE256 returns true if the SHAKE256 extendable output function is
// supported.
func SupportsSHAKE256() bool {
	return supportsSHAKE(256)
}

// SupportsCSHAKE128 returns true if the CSHAKE128 extendable output function is
// supported.
func SupportsCSHAKE128() bool {
	return false
}

// SupportsCSHAKE256 returns true if the CSHAKE256 extendable output function is
// supported.
func SupportsCSHAKE256() bool {
	return false
}

// cacheSHAKESupported is a cache of SHAKE size support.
var cacheSHAKESupported sync.Map

// SupportsSHAKE returns true if the SHAKE extendable output function is
// supported.
func supportsSHAKE(size int) bool {
	if vMajor == 1 || (vMajor == 3 && vMinor < 3) {
		// SHAKE MD's are supported since OpenSSL 1.1.1,
		// but EVP_DigestSqueeze is only supported since 3.3,
		// and we need it to implement [sha3.SHAKE].
		return false
	}
	if v, ok := cacheSHAKESupported.Load(size); ok {
		return v.(bool)
	}
	alg := loadShake(size)
	if alg == nil {
		cacheSHAKESupported.Store(size, false)
		return false
	}
	// EVP_MD objects can be non-nil even when they can't be used
	// in a EVP_MD_CTX, e.g. MD5 in FIPS mode. We need to prove
	// if they can be used by passing them to a EVP_MD_CTX.
	var supported bool
	if ctx := C.go_openssl_EVP_MD_CTX_new(); ctx != nil {
		supported = C.go_openssl_EVP_DigestInit_ex(ctx, alg.md, nil) == 1
		C.go_openssl_EVP_MD_CTX_free(ctx)
	}
	cacheSHAKESupported.Store(size, supported)
	return supported
}

// SHAKE is an instance of a SHAKE extendable output function.
type SHAKE struct {
	alg *shakeAlgorithm
	ctx C.GO_EVP_MD_CTX_PTR
}

// NewSHAKE128 creates a new SHAKE128 XOF.
func NewSHAKE128() *SHAKE {
	return newSHAKE(128)
}

// NewSHAKE256 creates a new SHAKE256 XOF.
func NewSHAKE256() *SHAKE {
	return newSHAKE(256)
}

// NewCSHAKE128 creates a new cSHAKE128 XOF.
//
// N is used to define functions based on cSHAKE, it can be empty when plain
// cSHAKE is desired. S is a customization byte string used for domain
// separation. When N and S are both empty, this is equivalent to NewSHAKE128.
func NewCSHAKE128(N, S []byte) *SHAKE {
	return nil
}

// NewCSHAKE256 creates a new cSHAKE256 XOF.
//
// N is used to define functions based on cSHAKE, it can be empty when plain
// cSHAKE is desired. S is a customization byte string used for domain
// separation. When N and S are both empty, this is equivalent to NewSHAKE256.
func NewCSHAKE256(N, S []byte) *SHAKE {
	return nil
}

func newSHAKE(size int) *SHAKE {
	if vMajor == 1 || (vMajor == 3 && vMinor < 3) {
		panic("openssl: SHAKE is not supported by this version of OpenSSL")

	}

	alg := loadShake(size)
	if alg == nil {
		panic("openssl: unsupported SHAKE" + strconv.Itoa(size) + " function")
	}
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		panic(newOpenSSLError("EVP_MD_CTX_new"))
	}
	if C.go_openssl_EVP_DigestInit_ex(ctx, alg.md, nil) != 1 {
		C.go_openssl_EVP_MD_CTX_free(ctx)
		panic(newOpenSSLError("EVP_DigestInit_ex"))
	}
	if C.go_openssl_EVP_MD_CTX_ctrl(ctx, C.EVP_MD_CTRL_XOF_LEN, C.int(alg.xofLength), nil) != 1 {
		C.go_openssl_EVP_MD_CTX_free(ctx)
		panic(newOpenSSLError("EVP_MD_CTX_ctrl"))
	}
	s := &SHAKE{ctx: ctx}
	runtime.SetFinalizer(s, (*SHAKE).finalize)
	return s
}

func (s *SHAKE) finalize() {
	C.go_openssl_EVP_MD_CTX_free(s.ctx)
}

// Write absorbs more data into the XOF's state.
//
// It panics if any output has already been read.
func (s *SHAKE) Write(p []byte) (n int, err error) {
	defer runtime.KeepAlive(s)
	if len(p) == 0 {
		return 0, nil
	}
	if C.go_openssl_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&*addr(p)), C.size_t(len(p))) != 1 {
		panic(newOpenSSLError("EVP_DigestUpdate"))
	}
	return len(p), nil
}

// Read squeezes more output from the XOF.
//
// Any call to Write after a call to Read will panic.
func (s *SHAKE) Read(p []byte) (n int, err error) {
	defer runtime.KeepAlive(s)
	if len(p) == 0 {
		return 0, nil
	}
	if C.go_openssl_EVP_DigestSqueeze(s.ctx, (*C.uchar)(unsafe.Pointer(&*addr(p))), C.size_t(len(p))) != 1 {
		panic(newOpenSSLError("EVP_DigestSqueeze"))
	}
	return len(p), nil
}

// Reset resets the XOF to its initial state.
func (s *SHAKE) Reset() {
	defer runtime.KeepAlive(s)
	if C.go_openssl_EVP_DigestInit_ex(s.ctx, nil, nil) != 1 {
		panic(newOpenSSLError("EVP_DigestInit_ex"))
	}
}

// BlockSize returns the rate of the XOF.
func (s *SHAKE) BlockSize() int {
	return s.alg.blockSize
}

// cacheSHAKE is a cache of SHAKE XOF length to GO_EVP_MD_PTR.
var cacheSHAKE sync.Map

type shakeAlgorithm struct {
	md        C.GO_EVP_MD_PTR
	blockSize int
	xofLength int
}

// loadShake converts a crypto.Hash to a EVP_MD.
func loadShake(xofLength int) *shakeAlgorithm {
	if v, ok := cacheMD.Load(xofLength); ok {
		return v.(*shakeAlgorithm)
	}

	var shake shakeAlgorithm
	switch xofLength {
	case 128:
		if versionAtOrAbove(1, 1, 0) {
			shake.md = C.go_openssl_EVP_shake128()
			shake.xofLength = 32
		}
	case 256:
		if versionAtOrAbove(1, 1, 0) {
			shake.md = C.go_openssl_EVP_shake256()
			shake.xofLength = 64
		}
	}
	if shake.md == nil {
		cacheMD.Store(xofLength, (*hashAlgorithm)(nil))
		return nil
	}
	shake.blockSize = int(C.go_openssl_EVP_MD_get_block_size(shake.md))
	if vMajor == 3 {
		md := C.go_openssl_EVP_MD_fetch(nil, C.go_openssl_EVP_MD_get0_name(shake.md), nil)
		// Don't overwrite md in case it can't be fetched, as the md may still be used
		// outside of EVP_MD_CTX.
		if md != nil {
			shake.md = md
		}
	}
	cacheMD.Store(xofLength, &shake)
	return &shake
}
