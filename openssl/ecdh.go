// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"runtime"
)

type PublicKeyECDH struct {
	curve string
	key   C.GO_EC_POINT_PTR
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	C.go_openssl_EC_POINT_free(k.key)
}

type PrivateKeyECDH struct {
	curve string
	key   C.GO_EC_KEY_PTR
}

func (k *PrivateKeyECDH) finalize() {
	C.go_openssl_EC_KEY_free(k.key)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) < 1 {
		return nil, errors.New("NewPublicKeyECDH: missing key")
	}

	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}

	group := C.go_openssl_EC_GROUP_new_by_curve_name(nid)
	if group == nil {
		return nil, newOpenSSLError("EC_GROUP_new_by_curve_name")
	}
	defer C.go_openssl_EC_GROUP_free(group)
	key := C.go_openssl_EC_POINT_new(group)
	if key == nil {
		return nil, newOpenSSLError("EC_POINT_new")
	}
	ok := C.go_openssl_EC_POINT_oct2point(group, key, base(bytes), C.size_t(len(bytes)), nil) != 0
	if !ok {
		C.go_openssl_EC_POINT_free(key)
		return nil, errors.New("point not on curve")
	}

	k := &PublicKeyECDH{curve, key, append([]byte(nil), bytes...)}
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	key := C.go_openssl_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, newOpenSSLError("EC_KEY_new_by_curve_name")
	}
	b := bytesToBN(bytes)
	ok := b != nil && C.go_openssl_EC_KEY_set_private_key(key, b) != 0
	if b != nil {
		C.go_openssl_BN_free(b)
	}
	if !ok {
		C.go_openssl_EC_KEY_free(key)
		return nil, newOpenSSLError("EC_KEY_set_private_key")
	}
	k := &PrivateKeyECDH{curve, key}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)

	group := C.go_openssl_EC_KEY_get0_group(k.key)
	if group == nil {
		return nil, newOpenSSLError("EC_KEY_get0_group")
	}
	kbig := C.go_openssl_EC_KEY_get0_private_key(k.key)
	if kbig == nil {
		return nil, newOpenSSLError("EC_KEY_get0_private_key")
	}
	pt := C.go_openssl_EC_POINT_new(group)
	if pt == nil {
		return nil, newOpenSSLError("EC_POINT_new")
	}
	if C.go_openssl_EC_POINT_mul(group, pt, kbig, nil, nil, nil) == 0 {
		C.go_openssl_EC_POINT_free(pt)
		return nil, newOpenSSLError("EC_POINT_mul")
	}
	bytes, err := pointBytesECDH(k.curve, group, pt)
	if err != nil {
		C.go_openssl_EC_POINT_free(pt)
		return nil, err
	}
	pub := &PublicKeyECDH{k.curve, pt, bytes}
	// Note: Same as in NewPublicKeyECDH regarding finalizer and KeepAlive.
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}

func pointBytesECDH(curve string, group C.GO_EC_GROUP_PTR, pt C.GO_EC_POINT_PTR) ([]byte, error) {
	out := make([]byte, 1+2*curveSize(curve))
	n := C.go_openssl_EC_POINT_point2oct(group, pt, C.GO_POINT_CONVERSION_UNCOMPRESSED, base(out), C.size_t(len(out)), nil)
	if int(n) != len(out) {
		return nil, newOpenSSLError("EC_POINT_point2oct")
	}
	return out, nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	group := C.go_openssl_EC_KEY_get0_group(priv.key)
	if group == nil {
		return nil, newOpenSSLError("EC_KEY_get0_group")
	}
	privBig := C.go_openssl_EC_KEY_get0_private_key(priv.key)
	if privBig == nil {
		return nil, newOpenSSLError("EC_KEY_get0_private_key")
	}
	pt := C.go_openssl_EC_POINT_new(group)
	if pt == nil {
		return nil, newOpenSSLError("EC_POINT_new")
	}
	defer C.go_openssl_EC_POINT_free(pt)
	if C.go_openssl_EC_POINT_mul(group, pt, nil, pub.key, privBig, nil) == 0 {
		return nil, newOpenSSLError("EC_POINT_mul")
	}
	out, err := xCoordBytesECDH(priv.curve, group, pt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func xCoordBytesECDH(curve string, group C.GO_EC_GROUP_PTR, pt C.GO_EC_POINT_PTR) ([]byte, error) {
	big := C.go_openssl_BN_new()
	defer C.go_openssl_BN_free(big)
	if C.go_openssl_EC_POINT_get_affine_coordinates_GFp(group, pt, big, nil, nil) == 0 {
		return nil, newOpenSSLError("EC_POINT_get_affine_coordinates_GFp")
	}
	return bigBytesECDH(curve, big)
}

func bigBytesECDH(curve string, big C.GO_BIGNUM_PTR) ([]byte, error) {
	out := make([]byte, curveSize(curve))
	if C.go_openssl_BN_bn2binpad(big, base(out), C.int(len(out))) == 0 {
		return nil, newOpenSSLError("BN_bn2binpad")
	}
	return out, nil
}

func curveSize(curve string) int {
	switch curve {
	default:
		panic("openssl: unknown curve " + curve)
	case "P-256":
		return 256 / 8
	case "P-384":
		return 384 / 8
	case "P-521":
		return (521 + 7) / 8
	}
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	pkey, err := generateEVPPKey(C.GO_EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, err
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	key := C.go_openssl_EVP_PKEY_get1_EC_KEY(pkey)
	if key == nil {
		return nil, nil, newOpenSSLError("EVP_PKEY_get1_EC_KEY")
	}
	group := C.go_openssl_EC_KEY_get0_group(key)
	if group == nil {
		C.go_openssl_EC_KEY_free(key)
		return nil, nil, newOpenSSLError("EC_KEY_get0_group")
	}
	b := C.go_openssl_EC_KEY_get0_private_key(key)
	if b == nil {
		C.go_openssl_EC_KEY_free(key)
		return nil, nil, newOpenSSLError("EC_KEY_get0_private_key")
	}
	bytes, err := bigBytesECDH(curve, b)
	if err != nil {
		C.go_openssl_EC_KEY_free(key)
		return nil, nil, err
	}

	k := &PrivateKeyECDH{curve, key}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}
