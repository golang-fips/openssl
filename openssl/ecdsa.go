//go:build linux && !android
// +build linux,!android

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
	pkey, err := newECKey(curve, X, Y, nil)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func NewPrivateKeyECDSA(curve string, X, Y, D BigInt) (*PrivateKeyECDSA, error) {
	pkey, err := newECKey(curve, X, Y, D)
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

	// Retrieve the internal EC_KEY, which holds the X, Y, and D coordinates.
	key := C.go_openssl_EVP_PKEY_get1_EC_KEY(pkey)
	if key == nil {
		return nil, nil, nil, newOpenSSLError("EVP_PKEY_get1_EC_KEY failed")
	}
	defer C.go_openssl_EC_KEY_free(key)

	// Allocate two big numbers to store the X and Y coordinates.
	bx, by := C.go_openssl_BN_new(), C.go_openssl_BN_new()
	defer func() {
		bnFree(bx)
		bnFree(by)
	}()
	if bx == nil || by == nil {
		return nil, nil, nil, newOpenSSLError("BN_new failed")
	}

	// Get X and Y.
	group := C.go_openssl_EC_KEY_get0_group(key)
	pt := C.go_openssl_EC_KEY_get0_public_key(key)
	if C.go_openssl_EC_POINT_get_affine_coordinates_GFp(group, pt, bx, by, nil) == 0 {
		return nil, nil, nil, newOpenSSLError("EC_POINT_get_affine_coordinates_GFp failed")
	}

	// Get D.
	bd := C.go_openssl_EC_KEY_get0_private_key(key)
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

func newECKey(curve string, X, Y, D BigInt) (C.GO_EVP_PKEY_PTR, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	// Create a new EC_KEY for the given curve.
	key := C.go_openssl_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name failed")
	}
	defer C.go_openssl_EC_KEY_free(key)

	// Convert X, Y, and D coordinates to OpenSSL format. D is optional and may be nil.
	bx, by, bd := bigToBN(X), bigToBN(Y), bigToBN(D)
	defer func() {
		bnFree(bx)
		bnFree(by)
		bnFree(bd)
	}()
	if bx == nil || by == nil || (D != nil && bd == nil) {
		return nil, newOpenSSLError("BN_lebin2bn failed")
	}

	// Set the public and private components.
	if C.go_openssl_EC_KEY_set_public_key_affine_coordinates(key, bx, by) != 1 {
		return nil, newOpenSSLError("EC_KEY_set_public_key_affine_coordinates failed")
	}
	if bd != nil && C.go_openssl_EC_KEY_set_private_key(key, bd) != 1 {
		return nil, newOpenSSLError("EC_KEY_set_private_key failed")
	}

	// Create the EVP_PKEY and assign it the EC_KEY.
	pkey := C.go_openssl_EVP_PKEY_new()
	if pkey == nil {
		return nil, newOpenSSLError("EVP_PKEY_new failed")
	}
	if C.go_openssl_EVP_PKEY_set1_EC_KEY(pkey, key) != 1 {
		C.go_openssl_EVP_PKEY_free(pkey)
		return nil, newOpenSSLError("EVP_PKEY_set1_EC_KEY failed")
	}
	return pkey, nil
}

func curveNID(curve string) (C.int, error) {
	switch curve {
	case "P-224":
		return C.GO_NID_secp224r1, nil
	case "P-256":
		return C.GO_NID_X9_62_prime256v1, nil
	case "P-384":
		return C.GO_NID_secp384r1, nil
	case "P-521":
		return C.GO_NID_secp521r1, nil
	}
	return 0, errUnknownCurve
}
