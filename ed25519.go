//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"strconv"
)

var (
	paramSigInstance           = C.CString("instance")
	paramSigInstanceEd25519ph  = C.CString("Ed25519ph")
	paramSigInstanceEd25519ctx = C.CString("Ed25519ctx")
	paramSigContext            = C.CString("context-string")
)

const (
	// publicKeySize is the size, in bytes, of public keys as used in crypto/ed25519.
	publicKeySizeEd25519 = 32
	// privateKeySize is the size, in bytes, of private keys as used in crypto/ed25519.
	privateKeySizeEd25519 = 64
	// signatureSize is the size, in bytes, of signatures generated and verified by crypto/ed25519.
	signatureSizeEd25519 = 64
	// seedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	seedSizeEd25519 = 32
)

type edDSAKind int

const (
	edDSAKindEd25519 edDSAKind = iota
	edDSAKindEd25519ph
	edDSAKindEd25519ctx
)

func SupportsEd25519() bool {
	return vMajor > 1 ||
		(vMajor >= 1 && vMinor > 1) ||
		(vMajor >= 1 && vMinor >= 1 && vPatch >= 1)
}

func SupportsEd25519ph() bool {
	return vMajor >= 3
}

func SupportsEd25519ctx() bool {
	return vMajor >= 3
}

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
	if l := len(seed); l != seedSizeEd25519 {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
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

func SignEd25519(priv, message []byte) (sig []byte, err error) {
	// Outline the function body so that the returned key can be stack-allocated.
	sig = make([]byte, signatureSizeEd25519)
	err = signEd25519(sig, priv, message, nil, edDSAKindEd25519)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func SignEd25519ph(priv, message, context []byte) (sig []byte, err error) {
	// Outline the function body so that the returned key can be stack-allocated.
	sig = make([]byte, signatureSizeEd25519)
	err = signEd25519(sig, priv, message, context, edDSAKindEd25519ph)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func SignEd25519ctx(priv, message, context []byte) (sig []byte, err error) {
	// Outline the function body so that the returned key can be stack-allocated.
	sig = make([]byte, signatureSizeEd25519)
	err = signEd25519(sig, priv, message, context, edDSAKindEd25519ctx)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func signEd25519(sig, priv, message, context []byte, kind edDSAKind) error {
	if l := len(priv); l != privateKeySizeEd25519 {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	if kind != edDSAKindEd25519 && vMajor == 1 {
		panic("ed25519: unsupported kind: " + strconv.Itoa(int(kind)))
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
	switch vMajor {
	case 1:
		if C.go_openssl_EVP_DigestSignInit(ctx, nil, nil, nil, pkey) != 1 {
			return newOpenSSLError("EVP_DigestSignInit")
		}
	case 3:
		params, err := ed25519Params(context, kind)
		if err != nil {
			return err
		}
		if params != nil {
			defer C.go_openssl_OSSL_PARAM_free(params)
		}
		if C.go_openssl_EVP_DigestSignInit_ex(ctx, nil, nil, nil, nil, pkey, params) != 1 {
			return newOpenSSLError("EVP_DigestSignInit_ex")
		}
	default:
		panic(errUnsupportedVersion())
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

func VerifyEd25519(pub, message, sig []byte) error {
	return verifyEd25519(pub, message, sig, nil, edDSAKindEd25519)
}

func VerifyEd25519ph(pub, message, sig, context []byte) error {
	return verifyEd25519(pub, message, sig, context, edDSAKindEd25519ph)
}

func VerifyEd25519ctx(pub, message, sig, context []byte) error {
	return verifyEd25519(pub, message, sig, context, edDSAKindEd25519ctx)
}

func verifyEd25519(pub, message, sig, context []byte, kind edDSAKind) error {
	if l := len(pub); l != publicKeySizeEd25519 {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
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
	switch vMajor {
	case 1:
		if C.go_openssl_EVP_DigestVerifyInit(ctx, nil, nil, nil, pkey) != 1 {
			return newOpenSSLError("EVP_DigestVerifyInit")
		}
	case 3:
		params, err := ed25519Params(context, kind)
		if err != nil {
			return err
		}
		if params != nil {
			defer C.go_openssl_OSSL_PARAM_free(params)
		}
		if C.go_openssl_EVP_DigestVerifyInit_ex(ctx, nil, nil, nil, nil, pkey, params) != 1 {
			return newOpenSSLError("EVP_DigestVerifyInit_ex")
		}
	default:
		panic(errUnsupportedVersion())
	}
	if C.go_openssl_EVP_DigestVerify(ctx, base(sig), C.size_t(len(sig)), base(message), C.size_t(len(message))) != 1 {
		return errors.New("ed25519: invalid signature")
	}
	return nil
}

func ed25519Params(context []byte, kind edDSAKind) (params C.GO_OSSL_PARAM_PTR, err error) {
	if kind == edDSAKindEd25519 {
		// Default parameters are fine.
		return nil, nil
	}
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	defer C.go_openssl_OSSL_PARAM_BLD_free(bld)

	switch kind {
	case edDSAKindEd25519ph:
		C.go_openssl_OSSL_PARAM_BLD_push_utf8_string(bld, paramSigInstance, paramSigInstanceEd25519ph, 0)
	case edDSAKindEd25519ctx:
		C.go_openssl_OSSL_PARAM_BLD_push_utf8_string(bld, paramSigInstance, paramSigInstanceEd25519ctx, 0)
	default:
		panic("ed25519: unsupported kind: " + strconv.Itoa(int(kind)))
	}
	cbytes := C.CBytes(context)
	defer C.free(cbytes)
	C.go_openssl_OSSL_PARAM_BLD_push_octet_string(bld, paramSigContext, cbytes, C.size_t(len(context)))
	params = C.go_openssl_OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_to_param")
	}
	return params, nil
}
