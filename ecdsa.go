//go:build !cmd_go_bootstrap

package openssl

import "C"
import (
	"crypto"
	"errors"
	"runtime"
)

type PrivateKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey _EVP_PKEY_PTR
}

func (k *PrivateKeyECDSA) finalize() {
	go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyECDSA) withKey(f func(_EVP_PKEY_PTR) error) error {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PublicKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey _EVP_PKEY_PTR
}

func (k *PublicKeyECDSA) finalize() {
	go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyECDSA) withKey(f func(_EVP_PKEY_PTR) error) error {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

var errUnknownCurve = errors.New("openssl: unknown elliptic curve")

func NewPublicKeyECDSA(curve string, x, y BigInt) (*PublicKeyECDSA, error) {
	pkey, err := newECDSAKey(curve, x, y, nil)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func NewPrivateKeyECDSA(curve string, x, y, d BigInt) (*PrivateKeyECDSA, error) {
	pkey, err := newECDSAKey(curve, x, y, d)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PrivateKeyECDSA).finalize)
	return k, nil
}

func GenerateKeyECDSA(curve string) (x, y, d BigInt, err error) {
	// Generate the private key.
	pkey, err := generateEVPPKey(_EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, nil, err
	}
	defer go_openssl_EVP_PKEY_free(pkey)

	var bx, by, bd _BIGNUM_PTR
	defer func() {
		go_openssl_BN_free(bx)
		go_openssl_BN_free(by)
	}()
	switch vMajor {
	case 1:
		// Retrieve the internal EC_KEY, which holds the X, Y, and D coordinates.
		key := getECKey(pkey)
		group := go_openssl_EC_KEY_get0_group(key)
		pt := go_openssl_EC_KEY_get0_public_key(key)
		// Allocate two big numbers to store the X and Y coordinates.
		bx, err = go_openssl_BN_new()
		if err != nil {
			return nil, nil, nil, err
		}
		by, err = go_openssl_BN_new()
		if err != nil {
			return nil, nil, nil, err
		}
		// Get X and Y.
		if _, err := go_openssl_EC_POINT_get_affine_coordinates_GFp(group, pt, bx, by, nil); err != nil {
			return nil, nil, nil, err
		}
		// Get Z. We don't need to free it, get0 does not increase the reference count.
		bd = go_openssl_EC_KEY_get0_private_key(key)
	case 3:
		if _, err := go_openssl_EVP_PKEY_get_bn_param(pkey, _OSSL_PKEY_PARAM_EC_PUB_X.ptr(), &bx); err != nil {
			return nil, nil, nil, err
		}
		if _, err := go_openssl_EVP_PKEY_get_bn_param(pkey, _OSSL_PKEY_PARAM_EC_PUB_Y.ptr(), &by); err != nil {
			return nil, nil, nil, err
		}
		if _, err := go_openssl_EVP_PKEY_get_bn_param(pkey, _OSSL_PKEY_PARAM_PRIV_KEY.ptr(), &bd); err != nil {
			return nil, nil, nil, err
		}
		defer go_openssl_BN_clear_free(bd)
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

func newECDSAKey(curve string, x, y, d BigInt) (_EVP_PKEY_PTR, error) {
	nid := curveNID(curve)
	bx, err := bigToBN(x)
	if err != nil {
		return nil, err
	}
	defer go_openssl_BN_free(bx)
	by, err := bigToBN(y)
	if err != nil {
		return nil, err
	}
	defer go_openssl_BN_free(by)
	var bd _BIGNUM_PTR
	if d != nil {
		bd, err = bigToBN(d)
		if err != nil {
			return nil, err
		}
		defer go_openssl_BN_clear_free(bd)
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

func newECDSAKey1(nid int32, bx, by, bd _BIGNUM_PTR) (pkey _EVP_PKEY_PTR, err error) {
	checkMajorVersion(1)

	key, err := go_openssl_EC_KEY_new_by_curve_name(nid)
	if err != nil {
		return nil, err
	}
	defer func() {
		if pkey == nil {
			defer go_openssl_EC_KEY_free(key)
		}
	}()
	if _, err := go_openssl_EC_KEY_set_public_key_affine_coordinates(key, bx, by); err != nil {
		return nil, err
	}
	if bd != nil {
		if _, err := go_openssl_EC_KEY_set_private_key(key, bd); err != nil {
			return nil, err
		}
	}

	return newEVPPKEY(key)
}

func newECDSAKey3(nid int32, bx, by, bd _BIGNUM_PTR) (_EVP_PKEY_PTR, error) {
	checkMajorVersion(3)

	// Create the encoded public key public key from bx and by.
	pubBytes, err := generateAndEncodeEcPublicKey(nid, func(group _EC_GROUP_PTR) (_EC_POINT_PTR, error) {
		pt, err := go_openssl_EC_POINT_new(group)
		if err != nil {
			return nil, err
		}
		if _, err := go_openssl_EC_POINT_set_affine_coordinates(group, pt, bx, by, nil); err != nil {
			go_openssl_EC_POINT_free(pt)
			return nil, err
		}
		return pt, nil
	})
	if err != nil {
		return nil, err
	}
	// Construct the parameters.
	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()
	bld.addUTF8String(_OSSL_PKEY_PARAM_GROUP_NAME, go_openssl_OBJ_nid2sn(nid), 0)
	bld.addOctetString(_OSSL_PKEY_PARAM_PUB_KEY, pubBytes)
	var selection int32
	if bd != nil {
		bld.addBN(_OSSL_PKEY_PARAM_PRIV_KEY, bd)
		selection = _EVP_PKEY_KEYPAIR
	} else {
		selection = _EVP_PKEY_PUBLIC_KEY
	}
	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer go_openssl_OSSL_PARAM_free(params)
	return newEvpFromParams(_EVP_PKEY_EC, selection, params)
}
