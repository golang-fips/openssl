//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"runtime"
)

type PrivateKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey C.GO_EVP_PKEY_PTR
}

func (k *PrivateKeyECDSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyECDSA) withKey(f func(C.GO_EVP_PKEY_PTR) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PublicKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey C.GO_EVP_PKEY_PTR
}

func (k *PublicKeyECDSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyECDSA) withKey(f func(C.GO_EVP_PKEY_PTR) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

var errUnknownCurve = errors.New("openssl: unknown elliptic curve")

func NewPublicKeyECDSA(curve string, X, Y BigInt) (*PublicKeyECDSA, error) {
	pkey, err := newECDSAKey(curve, X, Y, nil)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func NewPrivateKeyECDSA(curve string, X, Y, D BigInt) (*PrivateKeyECDSA, error) {
	pkey, err := newECDSAKey(curve, X, Y, D)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PrivateKeyECDSA).finalize)
	return k, nil
}

func GenerateKeyECDSA(curve string) (X, Y, D BigInt, err error) {
	// Generate the private key.
	pkey, err := generateEVPPKey(C.GO_EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, nil, err
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)

	var bx, by, bd C.GO_BIGNUM_PTR
	defer func() {
		C.go_openssl_BN_free(bx)
		C.go_openssl_BN_free(by)
	}()
	switch vMajor {
	case 1:
		// Retrieve the internal EC_KEY, which holds the X, Y, and D coordinates.
		key := getECKey(pkey)
		group := C.go_openssl_EC_KEY_get0_group(key)
		pt := C.go_openssl_EC_KEY_get0_public_key(key)
		// Allocate two big numbers to store the X and Y coordinates.
		bx, by = C.go_openssl_BN_new(), C.go_openssl_BN_new()
		if bx == nil || by == nil {
			return nil, nil, nil, newOpenSSLError("BN_new failed")
		}
		// Get X and Y.
		if C.go_openssl_EC_POINT_get_affine_coordinates_GFp(group, pt, bx, by, nil) == 0 {
			return nil, nil, nil, newOpenSSLError("EC_POINT_get_affine_coordinates_GFp failed")
		}
		// Get Z. We don't need to free it, get0 does not increase the reference count.
		bd = C.go_openssl_EC_KEY_get0_private_key(key)
	case 3:
		if C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramECPubX, &bx) != 1 ||
			C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramECPubY, &by) != 1 ||
			C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramPrivKey, &bd) != 1 {
			return nil, nil, nil, newOpenSSLError("EVP_PKEY_get_bn_param")
		}
		defer C.go_openssl_BN_clear_free(bd)
	default:
		panic(errUnsupportedVersion())
	}

	// Get D.
	return bnToBig(bx), bnToBig(by), bnToBig(bd), nil
}

func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte) ([]byte, error) {
	return evpSign(priv.withKey, 0, 0, 0, hash)
}

func HashSignECDSA(priv *PrivateKeyECDSA, h crypto.Hash, msg []byte) ([]byte, error) {
	return evpHashSign(priv.withKey, h, msg)
}

func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, sig []byte) bool {
	return evpVerify(pub.withKey, 0, 0, 0, sig, hash) == nil
}

func HashVerifyECDSA(pub *PublicKeyECDSA, h crypto.Hash, msg, sig []byte) bool {
	return evpHashVerify(pub.withKey, h, msg, sig) == nil
}

func newECDSAKey(curve string, X, Y, D BigInt) (C.GO_EVP_PKEY_PTR, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	var bx, by, bd C.GO_BIGNUM_PTR
	defer func() {
		C.go_openssl_BN_free(bx)
		C.go_openssl_BN_free(by)
		C.go_openssl_BN_clear_free(bd)
	}()
	bx = bigToBN(X)
	by = bigToBN(Y)
	bd = bigToBN(D)
	if bx == nil || by == nil || (D != nil && bd == nil) {
		return nil, newOpenSSLError("BN_lebin2bn failed")
	}
	switch vMajor {
	case 1:
		return newECDSAKey1(nid, bx, by, bd)
	case 3:
		return newECDSAKey3(nid, bx, by, bd)
	default:
		panic(errUnsupportedVersion())
	}
}

func newECDSAKey1(nid C.int, bx, by, bd C.GO_BIGNUM_PTR) (pkey C.GO_EVP_PKEY_PTR, err error) {
	if vMajor != 1 {
		panic("incorrect vMajor version")
	}
	key := C.go_openssl_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name failed")
	}
	defer func() {
		if pkey == nil {
			defer C.go_openssl_EC_KEY_free(key)
		}
	}()
	if C.go_openssl_EC_KEY_set_public_key_affine_coordinates(key, bx, by) != 1 {
		return nil, newOpenSSLError("EC_KEY_set_public_key_affine_coordinates failed")
	}
	if bd != nil && C.go_openssl_EC_KEY_set_private_key(key, bd) != 1 {
		return nil, newOpenSSLError("EC_KEY_set_private_key failed")
	}
	return newEVPPKEY(key)
}

func newECDSAKey3(nid C.int, bx, by, bd C.GO_BIGNUM_PTR) (C.GO_EVP_PKEY_PTR, error) {
	if vMajor != 3 {
		panic("incorrect vMajor version")
	}
	// Create the encoded public key public key from bx and by.
	pubBytes, err := generateAndEncodeEcPublicKey(nid, func(group C.GO_EC_GROUP_PTR) (C.GO_EC_POINT_PTR, error) {
		pt := C.go_openssl_EC_POINT_new(group)
		if pt == nil {
			return nil, newOpenSSLError("EC_POINT_new")
		}
		if C.go_openssl_EC_POINT_set_affine_coordinates(group, pt, bx, by, nil) != 1 {
			C.go_openssl_EC_POINT_free(pt)
			return nil, newOpenSSLError("EC_POINT_set_affine_coordinates")
		}
		return pt, nil
	})
	if err != nil {
		return nil, err
	}
	// Construct the parameters.
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	defer C.go_openssl_OSSL_PARAM_BLD_free(bld)
	C.go_openssl_OSSL_PARAM_BLD_push_utf8_string(bld, paramGroup, C.go_openssl_OBJ_nid2sn(nid), 0)
	cbytes := C.CBytes(pubBytes)
	defer C.free(cbytes)
	C.go_openssl_OSSL_PARAM_BLD_push_octet_string(bld, paramPubKey, cbytes, C.size_t(len(pubBytes)))
	var selection C.int
	if bd != nil {
		if C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, paramPrivKey, bd) != 1 {
			return nil, newOpenSSLError("OSSL_PARAM_BLD_push_BN")
		}
		selection = C.GO_EVP_PKEY_KEYPAIR
	} else {
		selection = C.GO_EVP_PKEY_PUBLIC_KEY
	}
	params := C.go_openssl_OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_to_param")
	}
	defer C.go_openssl_OSSL_PARAM_free(params)
	return newEvpFromParams(C.GO_EVP_PKEY_EC, selection, params)
}
