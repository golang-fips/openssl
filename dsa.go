//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"runtime"
	"unsafe"
)

var (
	paramPbits = C.CString("pbits")
	paramQbits = C.CString("qbits")
	paramP     = C.CString("p")
	paramQ     = C.CString("q")
	paramG     = C.CString("g")
)

// DSAParameters contains the DSA parameters.
type DSAParameters struct {
	P, Q, G BigInt
}

// PrivateKeyDSA represents a DSA private key.
type PrivateKeyDSA struct {
	DSAParameters
	X, Y BigInt

	_pkey C.GO_EVP_PKEY_PTR
}

func (k *PrivateKeyDSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyDSA) withKey(f func(C.GO_EVP_PKEY_PTR) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

// PublicKeyDSA represents a DSA public key.
type PublicKeyDSA struct {
	DSAParameters
	Y BigInt

	_pkey C.GO_EVP_PKEY_PTR
}

func (k *PublicKeyDSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyDSA) withKey(f func(C.GO_EVP_PKEY_PTR) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

// GenerateDSAParameters generates a set of DSA parameters.
func GenerateDSAParameters(L, N int) (DSAParameters, error) {
	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(C.GO_EVP_PKEY_DSA, nil)
	if ctx == nil {
		return DSAParameters{}, newOpenSSLError("EVP_PKEY_CTX_new_id failed")
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	if C.go_openssl_EVP_PKEY_paramgen_init(ctx) != 1 {
		return DSAParameters{}, newOpenSSLError("EVP_PKEY_paramgen_init failed")
	}
	if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_DSA, -1, C.GO_EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, C.int(L), nil) != 1 {
		return DSAParameters{}, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
	}
	if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_DSA, -1, C.GO_EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, C.int(N), nil) != 1 {
		return DSAParameters{}, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
	}
	var pkey C.GO_EVP_PKEY_PTR
	if C.go_openssl_EVP_PKEY_paramgen(ctx, &pkey) != 1 {
		return DSAParameters{}, newOpenSSLError("EVP_PKEY_paramgen failed")
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	var p, q, g C.GO_BIGNUM_PTR
	switch vMajor {
	case 1:
		dsa := getDSA(pkey)
		if vMinor == 0 {
			C.go_openssl_DSA_get0_pqg_backport(dsa, &p, &q, &g)
		} else {
			C.go_openssl_DSA_get0_pqg(dsa, &p, &q, &g)
		}
	case 3:
		defer func() {
			C.go_openssl_BN_free(p)
			C.go_openssl_BN_free(q)
			C.go_openssl_BN_free(g)
		}()
		if C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramP, &p) != 1 ||
			C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramQ, &q) != 1 ||
			C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramG, &g) != 1 {
			return DSAParameters{}, newOpenSSLError("EVP_PKEY_get_bn_param")
		}
	default:
		panic(errUnsupportedVersion())
	}

	return DSAParameters{
		P: bnToBig(p),
		Q: bnToBig(q),
		G: bnToBig(g),
	}, nil
}

// NewPrivateKeyDSA creates a new DSA private key from the given parameters.
func NewPrivateKeyDSA(params DSAParameters, X, Y BigInt) (*PrivateKeyDSA, error) {
	if X == nil || Y == nil {
		panic("X and Y must not be nil")
	}
	pkey, err := newDSA(params, X, Y)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyDSA{params, X, Y, pkey}
	runtime.SetFinalizer(k, (*PrivateKeyDSA).finalize)
	return k, nil
}

// NewPublicKeyDSA creates a new DSA public key from the given parameters.
func NewPublicKeyDSA(params DSAParameters, Y BigInt) (*PublicKeyDSA, error) {
	if Y == nil {
		panic("Y must not be nil")
	}
	pkey, err := newDSA(params, nil, Y)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyDSA{params, Y, pkey}
	runtime.SetFinalizer(k, (*PublicKeyDSA).finalize)
	return k, nil
}

// GenerateKeyDSA generates a new private DSA key using the given parameters.
func GenerateKeyDSA(params DSAParameters) (*PrivateKeyDSA, error) {
	pkey, err := newDSA(params, nil, nil)
	if err != nil {
		return nil, err
	}
	var x, y C.GO_BIGNUM_PTR
	switch vMajor {
	case 1:
		dsa := getDSA(pkey)
		if vMinor == 0 {
			C.go_openssl_DSA_get0_key_backport(dsa, &y, &x)
		} else {
			C.go_openssl_DSA_get0_key(dsa, &y, &x)
		}
	case 3:
		defer func() {
			C.go_openssl_BN_clear_free(x)
			C.go_openssl_BN_free(y)
		}()
		if C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramPubKey, &y) != 1 ||
			C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramPrivKey, &x) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_get_bn_param")
		}
	default:
		panic(errUnsupportedVersion())
	}
	k := &PrivateKeyDSA{params, bnToBig(x), bnToBig(y), pkey}
	runtime.SetFinalizer(k, (*PrivateKeyDSA).finalize)
	return k, nil
}

// SignDSA signs a hash (which should be the result of hashing a larger message).
func SignDSA(priv *PrivateKeyDSA, hash []byte) ([]byte, error) {
	return evpSign(priv.withKey, 0, 0, 0, hash)
}

// VerifyDSA verifiessig using the public key, pub.
func VerifyDSA(pub *PublicKeyDSA, hash []byte, sig []byte) bool {
	return evpVerify(pub.withKey, 0, 0, 0, sig, hash) == nil
}

func newDSA(params DSAParameters, X, Y BigInt) (C.GO_EVP_PKEY_PTR, error) {
	switch vMajor {
	case 1:
		return newDSA1(params, X, Y)
	case 3:
		return newDSA3(params, X, Y)
	default:
		panic(errUnsupportedVersion())
	}
}

func newDSA1(params DSAParameters, X, Y BigInt) (C.GO_EVP_PKEY_PTR, error) {
	if vMajor != 1 {
		panic("incorrect vMajor version")
	}
	dsa := C.go_openssl_DSA_new()
	p, q, g := bigToBN(params.P), bigToBN(params.Q), bigToBN(params.G)
	var ret C.int
	if vMinor == 0 {
		ret = C.go_openssl_DSA_set0_pqg_backport(dsa, p, q, g)
	} else {
		ret = C.go_openssl_DSA_set0_pqg(dsa, p, q, g)
	}
	if ret != 1 {
		C.go_openssl_BN_free(p)
		C.go_openssl_BN_free(q)
		C.go_openssl_BN_free(g)
		C.go_openssl_DSA_free(dsa)
		return nil, newOpenSSLError("DSA_set0_pqg failed")
	}
	if Y != nil {
		pub, priv := bigToBN(Y), bigToBN(X)
		if vMinor == 0 {
			ret = C.go_openssl_DSA_set0_key_backport(dsa, pub, priv)
		} else {
			ret = C.go_openssl_DSA_set0_key(dsa, pub, priv)
		}
		if ret != 1 {
			C.go_openssl_BN_free(pub)
			C.go_openssl_BN_clear_free(priv)
			C.go_openssl_DSA_free(dsa)
			return nil, newOpenSSLError("DSA_set0_key failed")
		}
	} else {
		if C.go_openssl_DSA_generate_key(dsa) != 1 {
			C.go_openssl_DSA_free(dsa)
			return nil, newOpenSSLError("DSA_generate_key failed")
		}
	}
	pkey := C.go_openssl_EVP_PKEY_new()
	if pkey == nil {
		C.go_openssl_DSA_free(dsa)
		return nil, newOpenSSLError("EVP_PKEY_new failed")
	}
	if C.go_openssl_EVP_PKEY_assign(pkey, C.GO_EVP_PKEY_DSA, unsafe.Pointer(dsa)) != 1 {
		C.go_openssl_DSA_free(dsa)
		C.go_openssl_EVP_PKEY_free(pkey)
		return nil, newOpenSSLError("EVP_PKEY_assign failed")
	}
	return pkey, nil
}

func newDSA3(params DSAParameters, X, Y BigInt) (C.GO_EVP_PKEY_PTR, error) {
	if vMajor != 3 {
		panic("incorrect vMajor version")
	}
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	defer C.go_openssl_OSSL_PARAM_BLD_free(bld)
	p, q, g := bigToBN(params.P), bigToBN(params.Q), bigToBN(params.G)
	defer func() {
		C.go_openssl_BN_free(p)
		C.go_openssl_BN_free(q)
		C.go_openssl_BN_free(g)
	}()
	if C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, paramP, p) != 1 ||
		C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, paramQ, q) != 1 ||
		C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, paramG, g) != 1 {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_push_BN")
	}
	selection := C.int(C.GO_EVP_PKEY_KEYPAIR)
	if Y != nil {
		pub := bigToBN(Y)
		defer C.go_openssl_BN_free(pub)
		if C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, paramPubKey, pub) != 1 {
			return nil, newOpenSSLError("OSSL_PARAM_BLD_push_BN")
		}
		if X == nil {
			selection = C.int(C.GO_EVP_PKEY_PUBLIC_KEY)
		}
	}
	if X != nil {
		priv := bigToBN(X)
		defer C.go_openssl_BN_clear_free(priv)
		if C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, paramPrivKey, priv) != 1 {
			return nil, newOpenSSLError("OSSL_PARAM_BLD_push_BN")
		}
	}
	bldparams := C.go_openssl_OSSL_PARAM_BLD_to_param(bld)
	if bldparams == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_to_param")
	}
	defer C.go_openssl_OSSL_PARAM_free(bldparams)
	pkey, err := newEvpFromParams(C.GO_EVP_PKEY_DSA, selection, bldparams)
	if err != nil {
		return nil, err
	}
	if Y != nil {
		return pkey, nil
	}
	// pkey doesn't contain the public/private components. We use it
	// as domain parameters placeholder to generate the final key.
	defer C.go_openssl_EVP_PKEY_free(pkey)
	ctx := C.go_openssl_EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new_from_pkey")
	}
	if C.go_openssl_EVP_PKEY_keygen_init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_keygen_init")
	}
	var gkey C.GO_EVP_PKEY_PTR
	if C.go_openssl_EVP_PKEY_keygen(ctx, &gkey) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_keygen")
	}
	return gkey, nil
}

// getDSA returns the DSA from pkey.
// If pkey does not contain an DSA it panics.
// The returned key should not be freed.
func getDSA(pkey C.GO_EVP_PKEY_PTR) (key C.GO_DSA_PTR) {
	if vMajor == 1 && vMinor == 0 {
		if key0 := C.go_openssl_EVP_PKEY_get0(pkey); key0 != nil {
			key = C.GO_DSA_PTR(key0)
		}
	} else {
		key = C.go_openssl_EVP_PKEY_get0_DSA(pkey)
	}
	if key == nil {
		panic("pkey does not contain an DSA")
	}
	return key
}
