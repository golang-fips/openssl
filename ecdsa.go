//go:build !cmd_go_bootstrap && cgo

package openssl

import (
	"crypto"
	"errors"
	"runtime"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

type PrivateKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey ossl.EVP_PKEY_PTR
}

func (k *PrivateKeyECDSA) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyECDSA) withKey(f func(ossl.EVP_PKEY_PTR) error) error {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PublicKeyECDSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey ossl.EVP_PKEY_PTR
}

func (k *PublicKeyECDSA) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyECDSA) withKey(f func(ossl.EVP_PKEY_PTR) error) error {
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
	fail := func(err error) (BigInt, BigInt, BigInt, error) {
		return nil, nil, nil, err
	}
	// Generate the private key.
	pkey, err := generateEVPPKey(ossl.EVP_PKEY_EC, 0, curve)
	if err != nil {
		return fail(err)
	}
	defer ossl.EVP_PKEY_free(pkey)

	var bx, by, bd ossl.BIGNUM_PTR
	defer func() {
		ossl.BN_free(bx)
		ossl.BN_free(by)
	}()
	switch vMajor {
	case 1:
		// Retrieve the internal EC_KEY, which holds the X, Y, and D coordinates.
		key := getECKey(pkey)
		group, err := ossl.EC_KEY_get0_group(key)
		if err != nil {
			return fail(err)
		}
		pt, err := ossl.EC_KEY_get0_public_key(key)
		if err != nil {
			return fail(err)
		}
		// Allocate two big numbers to store the X and Y coordinates.
		bx, err = ossl.BN_new()
		if err != nil {
			return fail(err)
		}
		by, err = ossl.BN_new()
		if err != nil {
			return fail(err)
		}
		// Get X and Y.
		if err := ossl.EC_POINT_get_affine_coordinates_GFp(group, pt, bx, by, nil); err != nil {
			return fail(err)
		}
		// Get Z. We don't need to free it, get0 does not increase the reference count.
		bd, err = ossl.EC_KEY_get0_private_key(key)
		if err != nil {
			return fail(err)
		}
	case 3:
		if err := getBnParam(pkey, ossl.OSSL_PKEY_PARAM_EC_PUB_X, &bx); err != nil {
			return fail(err)
		}
		if err := getBnParam(pkey, ossl.OSSL_PKEY_PARAM_EC_PUB_Y, &by); err != nil {
			return fail(err)
		}
		if err := getBnParam(pkey, ossl.OSSL_PKEY_PARAM_PRIV_KEY, &bd); err != nil {
			return fail(err)
		}
		defer ossl.BN_clear_free(bd)
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

func newECDSAKey(curve string, x, y, d BigInt) (ossl.EVP_PKEY_PTR, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	var bx, by, bd ossl.BIGNUM_PTR
	defer func() {
		ossl.BN_free(bx)
		ossl.BN_free(by)
		ossl.BN_clear_free(bd)
	}()
	bx = bigToBN(x)
	by = bigToBN(y)
	bd = bigToBN(d)
	if bx == nil || by == nil || (d != nil && bd == nil) {
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

func newECDSAKey1(nid int, bx, by, bd ossl.BIGNUM_PTR) (pkey ossl.EVP_PKEY_PTR, err error) {
	checkMajorVersion(1)

	key, err := ossl.EC_KEY_new_by_curve_name(int32(nid))
	if err != nil {
		return nil, err
	}
	defer func() {
		if pkey == nil {
			defer ossl.EC_KEY_free(key)
		}
	}()
	if err := ossl.EC_KEY_set_public_key_affine_coordinates(key, bx, by); err != nil {
		return nil, err
	}
	if bd != nil {
		if err := ossl.EC_KEY_set_private_key(key, bd); err != nil {
			return nil, err
		}
	}
	return newEVPPKEY(key)
}

func newECDSAKey3(nid int, bx, by, bd ossl.BIGNUM_PTR) (ossl.EVP_PKEY_PTR, error) {
	checkMajorVersion(3)

	// Create the encoded public key public key from bx and by.
	pubBytes, err := generateAndEncodeEcPublicKey(nid, func(group ossl.EC_GROUP_PTR) (ossl.EC_POINT_PTR, error) {
		pt, err := ossl.EC_POINT_new(group)
		if err != nil {
			return nil, err
		}
		if err := ossl.EC_POINT_set_affine_coordinates(group, pt, bx, by, nil); err != nil {
			ossl.EC_POINT_free(pt)
			return nil, newOpenSSLError("EC_POINT_set_affine_coordinates")
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
	bld.addUTF8String(ossl.OSSL_PKEY_PARAM_GROUP_NAME, ossl.OBJ_nid2sn(int32(nid)), 0)
	bld.addOctetString(ossl.OSSL_PKEY_PARAM_PUB_KEY, pubBytes)
	var selection int
	if bd != nil {
		bld.addBN(ossl.OSSL_PKEY_PARAM_PRIV_KEY, bd)
		selection = ossl.EVP_PKEY_KEYPAIR
	} else {
		selection = ossl.EVP_PKEY_PUBLIC_KEY
	}
	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)
	return newEvpFromParams(ossl.EVP_PKEY_EC, selection, params)
}
