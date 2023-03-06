//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

type PublicKeyECDH struct {
	_pkey C.GO_EVP_PKEY_PTR
	bytes []byte

	// priv is only set when PublicKeyECDH is derived from a private key,
	// in which case priv's finalizer is responsible for freeing _pkey.
	// This ensures priv is not finalized while the public key is alive,
	// which could cause use-after-free and double-free behavior.
	//
	// We could avoid this altogether by using EVP_PKEY_up_ref
	// when instantiating a derived public key, unfortunately
	// it is not available on OpenSSL 1.0.2.
	priv *PrivateKeyECDH
}

func (k *PublicKeyECDH) finalize() {
	if k.priv == nil {
		C.go_openssl_EVP_PKEY_free(k._pkey)
	}
}

type PrivateKeyECDH struct {
	_pkey        C.GO_EVP_PKEY_PTR
	curve        string
	hasPublicKey bool
}

func (k *PrivateKeyECDH) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) < 1 {
		return nil, errors.New("NewPublicKeyECDH: missing key")
	}
	pkey, err := newECDHPkey(curve, bytes, false)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDH{pkey, append([]byte(nil), bytes...), nil}
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	pkey, err := newECDHPkey(curve, bytes, true)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDH{pkey, curve, false}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	if !k.hasPublicKey {
		err := deriveEcdhPublicKey(k._pkey, k.curve)
		if err != nil {
			return nil, err
		}
		k.hasPublicKey = true
	}
	var bytes []byte
	switch vMajor {
	case 1:
		key := getECKey(k._pkey)
		pt := C.go_openssl_EC_KEY_get0_public_key(key)
		if pt == nil {
			return nil, newOpenSSLError("EC_KEY_get0_public_key")
		}
		group := C.go_openssl_EC_KEY_get0_group(key)
		var err error
		bytes, err = encodeEcPoint(group, pt)
		if err != nil {
			return nil, err
		}
	case 3:
		var cbytes *C.uchar
		n := C.go_openssl_EVP_PKEY_get1_encoded_public_key(k._pkey, &cbytes)
		if n == 0 {
			return nil, newOpenSSLError("EVP_PKEY_get_octet_string_param")
		}
		bytes = C.GoBytes(unsafe.Pointer(cbytes), C.int(n))
		C.free(unsafe.Pointer(cbytes))
	default:
		panic(errUnsupportedVersion())
	}
	pub := &PublicKeyECDH{k._pkey, bytes, k}
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}

func newECDHPkey(curve string, bytes []byte, isPrivate bool) (C.GO_EVP_PKEY_PTR, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	switch vMajor {
	case 1:
		return newECDHPkey1(nid, bytes, isPrivate)
	case 3:
		return newECDHPkey3(nid, bytes, isPrivate)
	default:
		panic(errUnsupportedVersion())
	}
}

func newECDHPkey1(nid C.int, bytes []byte, isPrivate bool) (pkey C.GO_EVP_PKEY_PTR, err error) {
	if vMajor != 1 {
		panic("incorrect vMajor version")
	}
	key := C.go_openssl_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name")
	}
	defer func() {
		if pkey == nil {
			C.go_openssl_EC_KEY_free(key)
		}
	}()
	if isPrivate {
		priv := C.go_openssl_BN_bin2bn(base(bytes), C.int(len(bytes)), nil)
		if priv == nil {
			return nil, newOpenSSLError("BN_bin2bn")
		}
		defer C.go_openssl_BN_free(priv)
		if C.go_openssl_EC_KEY_set_private_key(key, priv) != 1 {
			return nil, newOpenSSLError("EC_KEY_set_private_key")
		}
	} else {
		group := C.go_openssl_EC_KEY_get0_group(key)
		pub := C.go_openssl_EC_POINT_new(group)
		if pub == nil {
			return nil, newOpenSSLError("EC_POINT_new")
		}
		defer C.go_openssl_EC_POINT_free(pub)
		if C.go_openssl_EC_POINT_oct2point(group, pub, base(bytes), C.size_t(len(bytes)), nil) != 1 {
			return nil, errors.New("point not on curve")
		}
		if C.go_openssl_EC_KEY_set_public_key(key, pub) != 1 {
			return nil, newOpenSSLError("EC_KEY_set_public_key")
		}
	}
	return newEVPPKEY(key)
}

func newECDHPkey3(nid C.int, bytes []byte, isPrivate bool) (C.GO_EVP_PKEY_PTR, error) {
	if vMajor != 3 {
		panic("incorrect vMajor version")
	}
	params := newParamsBuilder()
	defer params.free()
	params.addUTF8(paramGroup, C.GoString(C.go_openssl_OBJ_nid2sn(nid)))
	var selection C.int
	if isPrivate {
		if err := params.addBigNumber(paramPrivKey, bytes); err != nil {
			return nil, err
		}
		selection = C.GO_EVP_PKEY_KEYPAIR
	} else {
		params.addOctetString(paramPubKey, bytes)
		selection = C.GO_EVP_PKEY_PUBLIC_KEY
	}
	return newEvpFromParams(C.GO_EVP_PKEY_EC, selection, params.params)
}

// deriveEcdhPublicKey sets the raw public key of pkey by deriving it from
// the raw private key.
func deriveEcdhPublicKey(pkey C.GO_EVP_PKEY_PTR, curve string) error {
	derive := func(group C.GO_EC_GROUP_PTR, priv C.GO_BIGNUM_PTR) (C.GO_EC_POINT_PTR, error) {
		// OpenSSL does not expose any method to generate the public
		// key from the private key [1], so we have to calculate it here.
		// [1] https://github.com/openssl/openssl/issues/18437#issuecomment-1144717206
		pt := C.go_openssl_EC_POINT_new(group)
		if pt == nil {
			return nil, newOpenSSLError("EC_POINT_new")
		}
		if C.go_openssl_EC_POINT_mul(group, pt, priv, nil, nil, nil) == 0 {
			C.go_openssl_EC_POINT_free(pt)
			return nil, newOpenSSLError("EC_POINT_mul")
		}
		return pt, nil
	}
	switch vMajor {
	case 1:
		key := getECKey(pkey)
		priv := C.go_openssl_EC_KEY_get0_private_key(key)
		if priv == nil {
			return newOpenSSLError("EC_KEY_get0_private_key")
		}
		group := C.go_openssl_EC_KEY_get0_group(key)
		pub, err := derive(group, priv)
		if err != nil {
			return err
		}
		defer C.go_openssl_EC_POINT_free(pub)
		if C.go_openssl_EC_KEY_set_public_key(key, pub) != 1 {
			return newOpenSSLError("EC_KEY_set_public_key")
		}
	case 3:
		var priv C.GO_BIGNUM_PTR
		if C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramPrivKey, &priv) != 1 {
			return newOpenSSLError("EVP_PKEY_get_bn_param")
		}
		defer C.go_openssl_BN_free(priv)
		nid, _ := curveNID(curve)
		pubBytes, err := generateAndEncodePublicKey(nid, func(group C.GO_EC_GROUP_PTR) (C.GO_EC_POINT_PTR, error) {
			return derive(group, priv)
		})
		if err != nil {
			return err
		}
		if C.go_openssl_EVP_PKEY_set1_encoded_public_key(pkey, base(pubBytes), C.size_t(len(pubBytes))) != 1 {
			return newOpenSSLError("EVP_PKEY_set1_encoded_public_key")
		}
	default:
		panic(errUnsupportedVersion())
	}
	return nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	defer runtime.KeepAlive(pub)
	ctx := C.go_openssl_EVP_PKEY_CTX_new(priv._pkey, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new")
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	if C.go_openssl_EVP_PKEY_derive_init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	if C.go_openssl_EVP_PKEY_derive_set_peer(ctx, pub._pkey) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_set_peer")
	}
	var outLen C.size_t
	if C.go_openssl_EVP_PKEY_derive(ctx, nil, &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	out := make([]byte, outLen)
	if C.go_openssl_EVP_PKEY_derive(ctx, base(out), &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	return out, nil
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	pkey, err := generateEVPPKey(C.GO_EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, err
	}
	var k *PrivateKeyECDH
	defer func() {
		if k == nil {
			C.go_openssl_EVP_PKEY_free(pkey)
		}
	}()
	var priv C.GO_BIGNUM_PTR
	switch vMajor {
	case 1:
		key := getECKey(pkey)
		priv = C.go_openssl_EC_KEY_get0_private_key(key)
		if priv == nil {
			return nil, nil, newOpenSSLError("EC_KEY_get0_private_key")
		}
	case 3:
		if C.go_openssl_EVP_PKEY_get_bn_param(pkey, paramPrivKey, &priv) != 1 {
			return nil, nil, newOpenSSLError("EVP_PKEY_get_bn_param")
		}
		defer C.go_openssl_BN_free(priv)
	default:
		panic(errUnsupportedVersion())
	}
	// We should not leak bit length of the secret scalar in the key.
	// For this reason, we use BN_bn2binpad instead of BN_bn2bin with fixed length.
	// The fixed length is the order of the large prime subgroup of the curve,
	// returned by EVP_PKEY_get_bits, which is generally the upper bound for
	// generating a private ECDH key.
	bits := C.go_openssl_EVP_PKEY_get_bits(pkey)
	bytes := make([]byte, (bits+7)/8)
	if C.go_openssl_BN_bn2binpad(priv, base(bytes), C.int(len(bytes))) == 0 {
		return nil, nil, newOpenSSLError("BN_bn2binpad")
	}
	k = &PrivateKeyECDH{pkey, curve, true}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}
