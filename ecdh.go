//go:build !cmd_go_bootstrap

package openssl

import "C"
import (
	"errors"
	"runtime"
	"slices"
	"unsafe"
)

type PublicKeyECDH struct {
	_pkey _EVP_PKEY_PTR
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	go_openssl_EVP_PKEY_free(k._pkey)
}

type PrivateKeyECDH struct {
	_pkey _EVP_PKEY_PTR
	curve string
}

func (k *PrivateKeyECDH) finalize() {
	go_openssl_EVP_PKEY_free(k._pkey)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) != 1+2*curveSize(curve) {
		return nil, errors.New("NewPublicKeyECDH: wrong key length")
	}
	pkey, err := newECDHPkey(curve, bytes, false)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDH{pkey, slices.Clone(bytes)}
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	if len(bytes) != curveSize(curve) {
		return nil, errors.New("NewPrivateKeyECDH: wrong key length")
	}
	pkey, err := newECDHPkey(curve, bytes, true)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDH{pkey, curve}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	var pkey _EVP_PKEY_PTR
	defer func() {
		go_openssl_EVP_PKEY_free(pkey)
	}()

	var bytes []byte
	switch vMajor {
	case 1:
		pkey = go_openssl_EVP_PKEY_new()
		if pkey == nil {
			return nil, newOpenSSLError("EVP_PKEY_new")
		}
		key := getECKey(k._pkey)
		if go_openssl_EVP_PKEY_set1_EC_KEY(pkey, key) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_set1_EC_KEY")
		}
		pt := go_openssl_EC_KEY_get0_public_key(key)
		if pt == nil {
			return nil, newOpenSSLError("EC_KEY_get0_public_key")
		}
		group := go_openssl_EC_KEY_get0_group(key)
		var err error
		bytes, err = encodeEcPoint(group, pt)
		if err != nil {
			return nil, err
		}
	case 3:
		pkey = k._pkey
		if go_openssl_EVP_PKEY_up_ref(pkey) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_up_ref")
		}

		var cbytes *byte
		n := go_openssl_EVP_PKEY_get1_encoded_public_key(k._pkey, &cbytes)
		if n == 0 {
			return nil, newOpenSSLError("EVP_PKEY_get_octet_string_param")
		}
		bytes = C.GoBytes(unsafe.Pointer(cbytes), C.int(n))
		cryptoFree(unsafe.Pointer(cbytes))
	default:
		panic(errUnsupportedVersion())
	}
	pub := &PublicKeyECDH{pkey, bytes}
	pkey = nil
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}

func newECDHPkey(curve string, bytes []byte, isPrivate bool) (_EVP_PKEY_PTR, error) {
	nid := curveNID(curve)
	switch vMajor {
	case 1:
		return newECDHPkey1(nid, bytes, isPrivate)
	case 3:
		return newECDHPkey3(nid, bytes, isPrivate)
	default:
		panic(errUnsupportedVersion())
	}
}

func newECDHPkey1(nid int32, bytes []byte, isPrivate bool) (pkey _EVP_PKEY_PTR, err error) {
	checkMajorVersion(1)

	key := go_openssl_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name")
	}
	defer func() {
		if pkey == nil {
			go_openssl_EC_KEY_free(key)
		}
	}()
	group := go_openssl_EC_KEY_get0_group(key)
	if isPrivate {
		priv := go_openssl_BN_bin2bn(base(bytes), int32(len(bytes)), nil)
		if priv == nil {
			return nil, newOpenSSLError("BN_bin2bn")
		}
		defer go_openssl_BN_clear_free(priv)
		if go_openssl_EC_KEY_set_private_key(key, priv) != 1 {
			return nil, newOpenSSLError("EC_KEY_set_private_key")
		}
		pub, err := pointMult(group, priv)
		if err != nil {
			return nil, err
		}
		defer go_openssl_EC_POINT_free(pub)
		if go_openssl_EC_KEY_set_public_key(key, pub) != 1 {
			return nil, newOpenSSLError("EC_KEY_set_public_key")
		}
	} else {
		pub := go_openssl_EC_POINT_new(group)
		if pub == nil {
			return nil, newOpenSSLError("EC_POINT_new")
		}
		defer go_openssl_EC_POINT_free(pub)
		if go_openssl_EC_POINT_oct2point(group, pub, base(bytes), len(bytes), nil) != 1 {
			return nil, errors.New("point not on curve")
		}
		if go_openssl_EC_KEY_set_public_key(key, pub) != 1 {
			return nil, newOpenSSLError("EC_KEY_set_public_key")
		}
	}
	if go_openssl_EC_KEY_check_key(key) != 1 {
		// Match upstream error message.
		if isPrivate {
			return nil, errors.New("crypto/ecdh: invalid private key")
		} else {
			return nil, errors.New("crypto/ecdh: invalid public key")
		}
	}
	return newEVPPKEY(key)
}

func newECDHPkey3(nid int32, bytes []byte, isPrivate bool) (_EVP_PKEY_PTR, error) {
	checkMajorVersion(3)

	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()
	bld.addUTF8String(_OSSL_PKEY_PARAM_GROUP_NAME, go_openssl_OBJ_nid2sn(nid), 0)
	var selection int32
	if isPrivate {
		priv := go_openssl_BN_bin2bn(base(bytes), int32(len(bytes)), nil)
		if priv == nil {
			return nil, newOpenSSLError("BN_bin2bn")
		}
		defer go_openssl_BN_clear_free(priv)
		pubBytes, err := generateAndEncodeEcPublicKey(nid, func(group _EC_GROUP_PTR) (_EC_POINT_PTR, error) {
			return pointMult(group, priv)
		})
		if err != nil {
			return nil, err
		}
		bld.addOctetString(_OSSL_PKEY_PARAM_PUB_KEY, pubBytes)
		bld.addBN(_OSSL_PKEY_PARAM_PRIV_KEY, priv)
		selection = _EVP_PKEY_KEYPAIR
	} else {
		bld.addOctetString(_OSSL_PKEY_PARAM_PUB_KEY, bytes)
		selection = _EVP_PKEY_PUBLIC_KEY
	}

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer go_openssl_OSSL_PARAM_free(params)
	pkey, err := newEvpFromParams(_EVP_PKEY_EC, selection, params)
	if err != nil {
		return nil, err
	}

	if err := checkPkey(pkey, isPrivate); err != nil {
		go_openssl_EVP_PKEY_free(pkey)
		return nil, errors.New("crypto/ecdh: " + err.Error())
	}
	return pkey, nil
}

func pointMult(group _EC_GROUP_PTR, priv _BIGNUM_PTR) (_EC_POINT_PTR, error) {
	// OpenSSL does not expose any method to generate the public
	// key from the private key [1], so we have to calculate it here.
	// [1] https://github.com/openssl/openssl/issues/18437#issuecomment-1144717206
	pt := go_openssl_EC_POINT_new(group)
	if pt == nil {
		return nil, newOpenSSLError("EC_POINT_new")
	}
	if go_openssl_EC_POINT_mul(group, pt, priv, nil, nil, nil) == 0 {
		go_openssl_EC_POINT_free(pt)
		return nil, newOpenSSLError("EC_POINT_mul")
	}
	return pt, nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	defer runtime.KeepAlive(pub)
	ctx := go_openssl_EVP_PKEY_CTX_new(priv._pkey, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new")
	}
	defer go_openssl_EVP_PKEY_CTX_free(ctx)
	if go_openssl_EVP_PKEY_derive_init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	if go_openssl_EVP_PKEY_derive_set_peer(ctx, pub._pkey) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_set_peer")
	}
	var keylen int
	if go_openssl_EVP_PKEY_derive(ctx, nil, &keylen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive")
	}
	out := make([]byte, keylen)
	if go_openssl_EVP_PKEY_derive(ctx, base(out), &keylen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive")
	}
	return out, nil
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	pkey, err := generateEVPPKey(_EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, err
	}
	var k *PrivateKeyECDH
	defer func() {
		if k == nil {
			go_openssl_EVP_PKEY_free(pkey)
		}
	}()
	var priv _BIGNUM_PTR
	switch vMajor {
	case 1:
		key := getECKey(pkey)
		priv = go_openssl_EC_KEY_get0_private_key(key)
		if priv == nil {
			return nil, nil, newOpenSSLError("EC_KEY_get0_private_key")
		}
	case 3:
		if go_openssl_EVP_PKEY_get_bn_param(pkey, _OSSL_PKEY_PARAM_PRIV_KEY.ptr(), &priv) != 1 {
			return nil, nil, newOpenSSLError("EVP_PKEY_get_bn_param")
		}
		defer go_openssl_BN_clear_free(priv)
	default:
		panic(errUnsupportedVersion())
	}
	// We should not leak bit length of the secret scalar in the key.
	// For this reason, we use BN_bn2binpad instead of BN_bn2bin with fixed length.
	// The fixed length is the order of the large prime subgroup of the curve,
	// returned by EVP_PKEY_get_bits, which is generally the upper bound for
	// generating a private ECDH key.
	bits := go_openssl_EVP_PKEY_get_bits(pkey)
	bytes := make([]byte, (bits+7)/8)
	if err := bnToBinPad(priv, bytes); err != nil {
		return nil, nil, err
	}
	k = &PrivateKeyECDH{pkey, curve}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}
