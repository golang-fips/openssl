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

func shakeOneShot(secuirtyBits int, data []byte, out []byte) bool {
	return C.go_openssl_EVP_Digest(unsafe.Pointer(&*addr(data)), C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&*addr(out))), nil, loadShake(secuirtyBits).md, nil) != 0
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

// SupportsSHAKE returns true if the SHAKE extendable output functions
// with the given securityBits are supported.
func SupportsSHAKE(securityBits int) bool {
	if vMajor == 1 || (vMajor == 3 && vMinor < 3) {
		// SHAKE MD's are supported since OpenSSL 1.1.1,
		// but EVP_DigestSqueeze is only supported since 3.3,
		// and we need it to implement [sha3.SHAKE].
		return false
	}
	return loadShake(securityBits) != nil
}

// SupportsCSHAKE returns true if the CSHAKE extendable output functions
// with the given securityBits are supported.
func SupportsCSHAKE(securityBits int) bool {
	return false
}

// SHAKE is an instance of a SHAKE extendable output function.
type SHAKE struct {
	alg        *shakeAlgorithm
	ctx        C.GO_EVP_MD_CTX_PTR
	lastXofLen int
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
	if len(N) == 0 && len(S) == 0 {
		return NewSHAKE128()
	}
	return nil
}

// NewCSHAKE256 creates a new cSHAKE256 XOF.
//
// N is used to define functions based on cSHAKE, it can be empty when plain
// cSHAKE is desired. S is a customization byte string used for domain
// separation. When N and S are both empty, this is equivalent to NewSHAKE256.
func NewCSHAKE256(N, S []byte) *SHAKE {
	if len(N) == 0 && len(S) == 0 {
		return NewSHAKE256()
	}
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
	s := &SHAKE{alg: alg, ctx: ctx}
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
	if len(p) != s.lastXofLen {
		if C.go_openssl_EVP_MD_CTX_ctrl(s.ctx, C.EVP_MD_CTRL_XOF_LEN, C.int(len(p)), nil) != 1 {
			panic(newOpenSSLError("EVP_MD_CTX_ctrl"))
		}
		s.lastXofLen = len(p)
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
	s.lastXofLen = 0
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
}

// loadShake converts a crypto.Hash to a EVP_MD.
func loadShake(securityBits int) (alg *shakeAlgorithm) {
	if v, ok := cacheMD.Load(securityBits); ok {
		return v.(*shakeAlgorithm)
	}
	defer func() {
		cacheMD.Store(securityBits, alg)
	}()

	var name *C.char
	switch securityBits {
	case 128:
		name = C.CString("SHAKE-128")
	case 256:
		name = C.CString("SHAKE-256")
	default:
		return nil
	}
	defer C.free(unsafe.Pointer(name))

	md := C.go_openssl_EVP_MD_fetch(nil, name, nil)
	if md == nil {
		return nil
	}

	alg = new(shakeAlgorithm)
	alg.md = md
	alg.blockSize = int(C.go_openssl_EVP_MD_get_block_size(md))
	return alg
}
