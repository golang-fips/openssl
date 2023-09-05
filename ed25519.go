//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"strconv"
	"sync"
	"unsafe"
)

const (
	// publicKeySizeEd25519 is the size, in bytes, of public keys as used in crypto/ed25519.
	publicKeySizeEd25519 = 32
	// privateKeySizeEd25519 is the size, in bytes, of private keys as used in crypto/ed25519.
	privateKeySizeEd25519 = 64
	// signatureSizeEd25519 is the size, in bytes, of signatures generated and verified by crypto/ed25519.
	signatureSizeEd25519 = 64
	// seedSizeEd25519 is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	seedSizeEd25519 = 32
)

// TODO: Add support for Ed25519ph and Ed25519ctx when OpenSSL supports them,
// which will probably be in 3.2.0 (https://github.com/openssl/openssl/issues/20418).

var (
	onceSupportsEd25519 sync.Once
	supportsEd25519     bool
)

// SupportsEd25519 returns true if the current OpenSSL version supports
// GenerateKeyEd25519, NewKeyFromSeedEd25519, SignEd25519 and VerifyEd25519.
func SupportsEd25519() bool {
	onceSupportsEd25519.Do(func() {
		switch vMajor {
		case 1:
			supportsEd25519 = version1_1_1_or_above()
		case 3:
			name := C.CString("ED25519")
			defer C.free(unsafe.Pointer(name))
			sig := C.go_openssl_EVP_SIGNATURE_fetch(nil, name, nil)
			if sig != nil {
				C.go_openssl_EVP_SIGNATURE_free(sig)
				supportsEd25519 = true
			}
		}
	})
	return supportsEd25519
}

// GenerateKeyEd25519 generates a public/private key pair.
func GenerateKeyEd25519() (pub, priv []byte, err error) {
	pkey, err := generateEVPPKey(C.GO_EVP_PKEY_ED25519, 0, "")
	if err != nil {
		return nil, nil, err
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	priv = make([]byte, privateKeySizeEd25519)
	err = extractPKEYPrivEd25519(pkey, priv)
	if err != nil {
		return nil, nil, err
	}
	pub = make([]byte, publicKeySizeEd25519)
	copy(pub, priv[seedSizeEd25519:])
	return pub, priv, nil
}

// NewKeyFromSeedEd25519 calculates a private key from a seed. It will panic if
// len(seed) is not [SeedSize]. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeedEd25519(seed []byte) (priv []byte, err error) {
	// Outline the function body so that the returned key can be stack-allocated.
	priv = make([]byte, privateKeySizeEd25519)
	err = newKeyFromSeedEd25519(priv, seed)
	if err != nil {
		return nil, err
	}
	return priv, err
}

func newKeyFromSeedEd25519(priv []byte, seed []byte) error {
	if len(seed) != seedSizeEd25519 {
		panic("ed25519: bad seed length: " + strconv.Itoa(len(seed)))
	}
	pkey := C.go_openssl_EVP_PKEY_new_raw_private_key(C.GO_EVP_PKEY_ED25519, nil, base(seed), C.size_t(len(seed)))
	if pkey == nil {
		return newOpenSSLError("EVP_PKEY_new_raw_private_key")
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	return extractPKEYPrivEd25519(pkey, priv)
}

func extractPKEYPrivEd25519(pkey C.GO_EVP_PKEY_PTR, priv []byte) error {
	pubSize, privSize := C.size_t(publicKeySizeEd25519), C.size_t(seedSizeEd25519)
	if C.go_openssl_EVP_PKEY_get_raw_public_key(pkey, base(priv[seedSizeEd25519:]), &pubSize) != 1 {
		return newOpenSSLError("EVP_PKEY_get_raw_public_key")
	}
	if pubSize != publicKeySizeEd25519 {
		panic("ed25519: bad public key length: " + strconv.Itoa(int(pubSize)))
	}
	if C.go_openssl_EVP_PKEY_get_raw_private_key(pkey, base(priv), &privSize) != 1 {
		return newOpenSSLError("EVP_PKEY_get_raw_private_key")
	}
	if privSize != seedSizeEd25519 {
		panic("ed25519: bad private key length: " + strconv.Itoa(int(privSize)))
	}
	return nil
}

// SignEd25519 signs the message with priv and returns a signature.
func SignEd25519(priv, message []byte) (sig []byte, err error) {
	// Outline the function body so that the returned key can be stack-allocated.
	sig = make([]byte, signatureSizeEd25519)
	err = signEd25519(sig, priv, message)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func signEd25519(sig, priv, message []byte) error {
	if len(priv) != privateKeySizeEd25519 {
		panic("ed25519: bad private key length: " + strconv.Itoa(len(priv)))
	}
	pkey := C.go_openssl_EVP_PKEY_new_raw_private_key(C.GO_EVP_PKEY_ED25519, nil, base(priv[:seedSizeEd25519]), seedSizeEd25519)
	if pkey == nil {
		return newOpenSSLError("EVP_PKEY_new_raw_private_key")
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return newOpenSSLError("EVP_MD_CTX_new")
	}
	defer C.go_openssl_EVP_MD_CTX_free(ctx)
	if C.go_openssl_EVP_DigestSignInit(ctx, nil, nil, nil, pkey) != 1 {
		return newOpenSSLError("EVP_DigestSignInit")
	}
	siglen := C.size_t(signatureSizeEd25519)
	if C.go_openssl_EVP_DigestSign(ctx, base(sig), &siglen, base(message), C.size_t(len(message))) != 1 {
		return newOpenSSLError("EVP_DigestSign")
	}
	if siglen != signatureSizeEd25519 {
		panic("ed25519: bad signature length: " + strconv.Itoa(int(siglen)))
	}
	return nil
}

// VerifyEd25519 reports whether sig is a valid signature of message by pub.
func VerifyEd25519(pub, message, sig []byte) error {
	if len(pub) != publicKeySizeEd25519 {
		panic("ed25519: bad public key length: " + strconv.Itoa(len(pub)))
	}
	pkey := C.go_openssl_EVP_PKEY_new_raw_public_key(C.GO_EVP_PKEY_ED25519, nil, base(pub), publicKeySizeEd25519)
	if pkey == nil {
		return newOpenSSLError("EVP_PKEY_new_raw_public_key")
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return newOpenSSLError("EVP_MD_CTX_new")
	}
	defer C.go_openssl_EVP_MD_CTX_free(ctx)
	if C.go_openssl_EVP_DigestVerifyInit(ctx, nil, nil, nil, pkey) != 1 {
		return newOpenSSLError("EVP_DigestVerifyInit")
	}
	if C.go_openssl_EVP_DigestVerify(ctx, base(sig), C.size_t(len(sig)), base(message), C.size_t(len(message))) != 1 {
		return errors.New("ed25519: invalid signature")
	}
	return nil
}
