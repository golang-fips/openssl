//go:build !cmd_go_bootstrap

package openssl

import (
	"runtime"
	"strconv"
	"sync"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// shakeOneShot applies the SHAKE extendable output function to data and
// writes the output to out.
func shakeOneShot(secuirtyBits int, data []byte, out []byte) {
	// Can't use EVP_Digest because it doesn't support output lengths
	// larger than the block size, while crypto/sha3 supports any length.
	alg := loadShake(secuirtyBits)
	if alg == nil {
		panic("openssl: unsupported SHAKE" + strconv.Itoa(secuirtyBits) + " function")
	}
	ctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		panic(err)
	}
	defer ossl.EVP_MD_CTX_free(ctx)
	if _, err := ossl.EVP_DigestInit_ex(ctx, alg.md, nil); err != nil {
		panic(err)
	}
	if _, err := ossl.EVP_DigestUpdate(ctx, data); err != nil {
		panic(err)
	}
	if _, err := ossl.EVP_DigestFinalXOF(ctx, out); err != nil {
		panic(err)
	}
}

// SumSHAKE128 applies the SHAKE128 extendable output function to data and
// returns an output of the given length in bytes.
func SumSHAKE128(data []byte, length int) []byte {
	out := make([]byte, length)
	shakeOneShot(128, data, out)
	return out
}

// SumSHAKE256 applies the SHAKE256 extendable output function to data and
// returns an output of the given length in bytes.
func SumSHAKE256(data []byte, length int) []byte {
	out := make([]byte, length)
	shakeOneShot(256, data, out)
	return out
}

var shakeSupported sync.Map

// SupportsSHAKE returns true if the SHAKE extendable output functions
// with the given securityBits are supported.
func SupportsSHAKE(securityBits int) bool {
	if major() == 1 || (major() == 3 && minor() < 3) {
		// SHAKE MD's are supported since OpenSSL 1.1.1,
		// but EVP_DigestSqueeze is only supported since 3.3,
		// and we need it to implement [sha3.SHAKE].
		return false
	}
	if v, ok := shakeSupported.Load(securityBits); ok {
		return v.(bool)
	}
	alg := loadShake(securityBits)
	if alg == nil {
		shakeSupported.Store(securityBits, false)
		return false
	}
	// EVP_MD objects can be non-nil but the underlying provider may not
	// support EVP_DigestSqueeze. We need to test it.
	var supported bool
	if ctx, _ := ossl.EVP_MD_CTX_new(); ctx != nil {
		defer ossl.EVP_MD_CTX_free(ctx)
		if _, err := ossl.EVP_DigestInit_ex(ctx, alg.md, nil); err == nil {
			var tmp [1]byte
			_, err := ossl.EVP_DigestSqueeze(ctx, tmp[:])
			supported = err == nil
		}
	}
	shakeSupported.Store(securityBits, supported)
	return supported
}

// SupportsCSHAKE returns true if the CSHAKE extendable output functions
// with the given securityBits are supported.
func SupportsCSHAKE(securityBits int) bool {
	// OpenSSL tracker issue https://github.com/openssl/openssl/issues/28358
	return false
}

// SHAKE is an instance of a SHAKE extendable output function.
type SHAKE struct {
	alg        *shakeAlgorithm
	ctx        ossl.EVP_MD_CTX_PTR
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

func newSHAKE(securityBits int) *SHAKE {
	alg := loadShake(securityBits)
	if alg == nil {
		panic("openssl: unsupported SHAKE" + strconv.Itoa(securityBits) + " function")
	}
	ctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		panic(err)
	}
	if _, err := ossl.EVP_DigestInit_ex(ctx, alg.md, nil); err != nil {
		ossl.EVP_MD_CTX_free(ctx)
		panic(err)
	}
	s := &SHAKE{alg: alg, ctx: ctx}
	runtime.SetFinalizer(s, (*SHAKE).finalize)
	return s
}

func (s *SHAKE) finalize() {
	ossl.EVP_MD_CTX_free(s.ctx)
}

// Write absorbs more data into the XOF's state.
//
// It panics if any output has already been read.
func (s *SHAKE) Write(p []byte) (n int, err error) {
	defer runtime.KeepAlive(s)
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := ossl.EVP_DigestUpdate(s.ctx, p); err != nil {
		panic(err)
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
		if _, err := ossl.EVP_MD_CTX_ctrl(s.ctx, ossl.EVP_MD_CTRL_XOF_LEN, int32(len(p)), nil); err != nil {
			panic(err)
		}
		s.lastXofLen = len(p)
	}
	if _, err := ossl.EVP_DigestSqueeze(s.ctx, p); err != nil {
		panic(err)
	}
	return len(p), nil
}

// Reset resets the XOF to its initial state.
func (s *SHAKE) Reset() {
	defer runtime.KeepAlive(s)
	if _, err := ossl.EVP_DigestInit_ex(s.ctx, nil, nil); err != nil {
		panic(err)
	}
	s.lastXofLen = 0
}

// BlockSize returns the rate of the XOF.
func (s *SHAKE) BlockSize() int {
	return s.alg.blockSize
}

func (s *SHAKE) MarshalBinary() ([]byte, error) {
	return nil, errMarshallUnsupported{}
}

func (s *SHAKE) AppendBinary(b []byte) ([]byte, error) {
	return nil, errMarshallUnsupported{}
}

func (s *SHAKE) UnmarshalBinary(data []byte) error {
	return errMarshallUnsupported{}
}

type shakeAlgorithm struct {
	md        ossl.EVP_MD_PTR
	blockSize int
}

var cacheSHAKE sync.Map

// loadShake converts a crypto.Hash to a EVP_MD.
func loadShake(securityBits int) (alg *shakeAlgorithm) {
	if v, ok := cacheSHAKE.Load(securityBits); ok {
		return v.(*shakeAlgorithm)
	}
	defer func() {
		cacheSHAKE.Store(securityBits, alg)
	}()

	var name cString
	switch securityBits {
	case 128:
		name = _DigestNameSHAKE128
	case 256:
		name = _DigestNameSHAKE256
	default:
		return nil
	}

	md, err := ossl.EVP_MD_fetch(nil, name.ptr(), nil)
	if err != nil || md == nil {
		return nil
	}

	alg = new(shakeAlgorithm)
	alg.md = md
	alg.blockSize = int(ossl.EVP_MD_get_block_size(md))
	return alg
}
