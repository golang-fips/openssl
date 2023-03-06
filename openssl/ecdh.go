// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

// #include "goopenssl.h"
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

var (
	paramPrivKey = C.CString("priv")
)

type PublicKeyECDH struct {
	_pkey *C.GO_EVP_PKEY
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
		C._goboringcrypto_EVP_PKEY_free(k._pkey)
	}
}

type PrivateKeyECDH struct {
	_pkey        *C.GO_EVP_PKEY
	curve        string
	hasPublicKey bool
}

func (k *PrivateKeyECDH) finalize() {
	C._goboringcrypto_EVP_PKEY_free(k._pkey)
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
	if openSSLVersion() < OPENSSL_VERSION_3_0_0 {
		key := getECKey(k._pkey)
		pt := C._goboringcrypto_EC_KEY_get0_public_key(key)
		if pt == nil {
			return nil, NewOpenSSLError("EC_KEY_get0_public_key")
		}
		group := C._goboringcrypto_EC_KEY_get0_group(key)
		var err error
		bytes, err = encodeEcPoint(group, pt)
		if err != nil {
			return nil, err
		}
	} else {
		var cbytes *C.uchar
		n := C._goboringcrypto_EVP_PKEY_get1_encoded_public_key(k._pkey, &cbytes)
		if n == 0 {
			return nil, NewOpenSSLError("EVP_PKEY_get_octet_string_param")
		}
		bytes = C.GoBytes(unsafe.Pointer(cbytes), C.int(n))
		C.free(unsafe.Pointer(cbytes))
	}
	pub := &PublicKeyECDH{k._pkey, bytes, k}
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}

func newECDHPkey(curve string, bytes []byte, isPrivate bool) (*C.GO_EVP_PKEY, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}

	var isPrivateValue C.int
	if isPrivate {
		isPrivateValue = 1
	}

	key := C._goboringcrypto_EVP_PKEY_new_for_ecdh(nid, base(bytes), C.size_t(len(bytes)), isPrivateValue)
	if key == nil {
		return nil, NewOpenSSLError("EVP_PKEY_new_for_ecdh")
	}
	return key, nil
}

// deriveEcdhPublicKey sets the raw public key of pkey by deriving it from
// the raw private key.
func deriveEcdhPublicKey(pkey *C.GO_EVP_PKEY, curve string) error {
	derive := func(group *C.GO_EC_GROUP, priv *C.GO_BIGNUM) (*C.GO_EC_POINT, error) {
		// OpenSSL does not expose any method to generate the public
		// key from the private key [1], so we have to calculate it here.
		// [1] https://github.com/openssl/openssl/issues/18437#issuecomment-1144717206
		pt := C._goboringcrypto_EC_POINT_new(group)
		if pt == nil {
			return nil, NewOpenSSLError("EC_POINT_new")
		}
		if C._goboringcrypto_EC_POINT_mul(group, pt, priv, nil, nil, nil) == 0 {
			C._goboringcrypto_EC_POINT_free(pt)
			return nil, NewOpenSSLError("EC_POINT_mul")
		}
		return pt, nil
	}
	if openSSLVersion() < OPENSSL_VERSION_3_0_0 {
		key := getECKey(pkey)
		priv := C._goboringcrypto_EC_KEY_get0_private_key(key)
		if priv == nil {
			return NewOpenSSLError("EC_KEY_get0_private_key")
		}
		group := C._goboringcrypto_EC_KEY_get0_group(key)
		pub, err := derive(group, priv)
		if err != nil {
			return err
		}
		defer C._goboringcrypto_EC_POINT_free(pub)
		if C._goboringcrypto_EC_KEY_set_public_key(key, pub) != 1 {
			return NewOpenSSLError("EC_KEY_set_public_key")
		}
	} else {
		var priv *C.GO_BIGNUM
		if C._goboringcrypto_EVP_PKEY_get_bn_param(pkey, paramPrivKey, &priv) != 1 {
			return NewOpenSSLError("EVP_PKEY_get_bn_param")
		}
		defer C._goboringcrypto_BN_free(priv)
		nid, _ := curveNID(curve)
		group := C._goboringcrypto_EC_GROUP_new_by_curve_name(nid)
		if group == nil {
			return NewOpenSSLError("EC_GROUP_new_by_curve_name")
		}
		defer C._goboringcrypto_EC_GROUP_free(group)
		pt, err := derive(group, priv)
		if err != nil {
			return err
		}
		defer C._goboringcrypto_EC_POINT_free(pt)
		pubBytes, err := encodeEcPoint(group, pt)
		if err != nil {
			return err
		}
		if C._goboringcrypto_EVP_PKEY_set1_encoded_public_key(pkey, base(pubBytes), C.size_t(len(pubBytes))) != 1 {
			return NewOpenSSLError("EVP_PKEY_set1_encoded_public_key")
		}
	}
	return nil
}

func encodeEcPoint(group *C.GO_EC_GROUP, pt *C.GO_EC_POINT) ([]byte, error) {
	// Get encoded point size.
	n := C._goboringcrypto_EC_POINT_point2oct(group, pt, C.GO_POINT_CONVERSION_UNCOMPRESSED, nil, 0, nil)
	if n == 0 {
		return nil, NewOpenSSLError("EC_POINT_point2oct")
	}
	// Encode point into bytes.
	bytes := make([]byte, n)
	n = C._goboringcrypto_EC_POINT_point2oct(group, pt, C.GO_POINT_CONVERSION_UNCOMPRESSED, base(bytes), n, nil)
	if n == 0 {
		return nil, NewOpenSSLError("EC_POINT_point2oct")
	}
	return bytes, nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	defer runtime.KeepAlive(pub)
	ctx := C._goboringcrypto_EVP_PKEY_CTX_new(priv._pkey, nil)
	if ctx == nil {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_new")
	}
	defer C._goboringcrypto_EVP_PKEY_CTX_free(ctx)
	if C._goboringcrypto_EVP_PKEY_derive_init(ctx) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init")
	}
	if C._goboringcrypto_EVP_PKEY_derive_set_peer_ex(ctx, pub._pkey, 1) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_set_peer_ex")
	}
	var outLen C.size_t
	if C._goboringcrypto_EVP_PKEY_derive(ctx, nil, &outLen) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init")
	}
	out := make([]byte, outLen)
	if C._goboringcrypto_EVP_PKEY_derive(ctx, base(out), &outLen) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init")
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
			C._goboringcrypto_EVP_PKEY_free(pkey)
		}
	}()
	var priv *C.GO_BIGNUM
	if openSSLVersion() < OPENSSL_VERSION_3_0_0 {
		key := getECKey(pkey)
		priv = C._goboringcrypto_EC_KEY_get0_private_key(key)
		if priv == nil {
			return nil, nil, NewOpenSSLError("EC_KEY_get0_private_key")
		}
	} else {
		if C._goboringcrypto_EVP_PKEY_get_bn_param(pkey, paramPrivKey, &priv) != 1 {
			return nil, nil, NewOpenSSLError("EVP_PKEY_get_bn_param")
		}
		defer C._goboringcrypto_BN_free(priv)
	}
	// We should not leak bit length of the secret scalar in the key.
	// For this reason, we use BN_bn2binpad instead of BN_bn2bin with fixed length.
	// The fixed length is the order of the large prime subgroup of the curve,
	// returned by EVP_PKEY_get_bits, which is generally the upper bound for
	// generating a private ECDH key.
	bits := C._goboringcrypto_EVP_PKEY_get_bits(pkey)
	bytes := make([]byte, (bits+7)/8)
	if C._goboringcrypto_BN_bn2binpad(priv, base(bytes), C.int(len(bytes))) == 0 {
		return nil, nil, NewOpenSSLError("BN_bn2binpad")
	}
	k = &PrivateKeyECDH{pkey, curve, true}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}
