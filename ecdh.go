//go:build !cmd_go_bootstrap

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
}

func (k *PublicKeyECDH) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
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
	k := &PublicKeyECDH{pkey, append([]byte(nil), bytes...)}
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
	var pkey C.GO_EVP_PKEY_PTR
	defer func() {
		C.go_openssl_EVP_PKEY_free(pkey)
	}()

	var bytes []byte
	switch vMajor {
	case 1:
		pkey = C.go_openssl_EVP_PKEY_new()
		if pkey == nil {
			return nil, newOpenSSLError("EVP_PKEY_new")
		}
		key := getECKey(k._pkey)
		if C.go_openssl_EVP_PKEY_set1_EC_KEY(pkey, key) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_set1_EC_KEY")
		}
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
		pkey = k._pkey
		if C.go_openssl_EVP_PKEY_up_ref(pkey) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_up_ref")
		}

		var cbytes *C.uchar
		n := C.go_openssl_EVP_PKEY_get1_encoded_public_key(k._pkey, &cbytes)
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
	checkMajorVersion(1)

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
		defer C.go_openssl_BN_clear_free(priv)
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
	checkMajorVersion(3)

	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	defer C.go_openssl_OSSL_PARAM_BLD_free(bld)
	C.go_openssl_OSSL_PARAM_BLD_push_utf8_string(bld, paramGroup, C.go_openssl_OBJ_nid2sn(nid), 0)
	var selection C.int
	if isPrivate {
		priv := C.go_openssl_BN_bin2bn(base(bytes), C.int(len(bytes)), nil)
		if priv == nil {
			return nil, newOpenSSLError("BN_bin2bn")
		}
		defer C.go_openssl_BN_clear_free(priv)
		if C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, paramPrivKey, priv) != 1 {
			return nil, newOpenSSLError("OSSL_PARAM_BLD_push_BN")
		}
		selection = C.GO_EVP_PKEY_KEYPAIR
	} else {
		cbytes := C.CBytes(bytes)
		defer C.free(cbytes)
		C.go_openssl_OSSL_PARAM_BLD_push_octet_string(bld, paramPubKey, cbytes, C.size_t(len(bytes)))
		selection = C.GO_EVP_PKEY_PUBLIC_KEY
	}
	params := C.go_openssl_OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_to_param")
	}
	defer C.go_openssl_OSSL_PARAM_free(params)
	return newEvpFromParams(C.GO_EVP_PKEY_EC, selection, params)
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
		defer C.go_openssl_BN_clear_free(priv)
		nid, _ := curveNID(curve)
		pubBytes, err := generateAndEncodeEcPublicKey(nid, func(group C.GO_EC_GROUP_PTR) (C.GO_EC_POINT_PTR, error) {
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
	r := C.go_openssl_EVP_PKEY_derive_wrapper(ctx, nil, 0)
	if r.result != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive_init")
	}
	out := make([]byte, r.keylen)
	if C.go_openssl_EVP_PKEY_derive_wrapper(ctx, base(out), r.keylen).result != 1 {
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
		defer C.go_openssl_BN_clear_free(priv)
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
	if err := bnToBinPad(priv, bytes); err != nil {
		return nil, nil, err
	}
	k = &PrivateKeyECDH{pkey, curve, true}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}
