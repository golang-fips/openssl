package sha3

// Drop-in replacement for golang.org/x/crypto/sha3
// Assumes openssl.Init() was called

import (
	"crypto"
	"hash"
	"github.com/golang-fips/openssl"
)

func init() {
	crypto.RegisterHash(crypto.SHA3_224, openssl.NewSHA3_224)
	crypto.RegisterHash(crypto.SHA3_256, openssl.NewSHA3_256)
	crypto.RegisterHash(crypto.SHA3_384, openssl.NewSHA3_384)
	crypto.RegisterHash(crypto.SHA3_512, openssl.NewSHA3_512)
}

func New224() hash.Hash {
	return openssl.NewSHA3_224()
}
func New256() hash.Hash {
	return openssl.NewSHA3_256()
}
func New384() hash.Hash {
	return openssl.NewSHA3_384()
}
func New512() hash.Hash {
	return openssl.NewSHA3_512()
}
func Sum224(p []byte) (sum [28]byte) {
	return openssl.SHA3_224(p)
}

func Sum256(p []byte) (sum [32]byte) {
	return openssl.SHA3_256(p)
}

func Sum384(p []byte) (sum [48]byte) {
	return openssl.SHA3_384(p)
}

func Sum512(p []byte) (sum [64]byte) {
	return openssl.SHA3_512(p)
}
