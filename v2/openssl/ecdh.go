// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

// #include "goopenssl.h"
import "C"
import "runtime"

// ECDH keys are compatible with ECDSA
type PublicKeyECDH = PublicKeyECDSA
type PrivateKeyECDH = PrivateKeyECDSA

var NewPublicKeyECDH = NewPublicKeyECDSA
var NewPrivateKeyECDH = NewPrivateKeyECDSA
var GenerateKeyECDH = GenerateKeyECDSA

func (k *PrivateKeyECDH) withKey(f func(*C.GO_EC_KEY) C.int) C.int {
	// Because of the finalizer, any time _key is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k.key)
}

func (k *PublicKeyECDH) withKey(f func(*C.GO_EC_KEY) C.int) C.int {
	// Because of the finalizer, any time _key is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k.key)
}

func getPeerKey(priv *PrivateKeyECDH, pubBytes []byte) (*PublicKeyECDH, error) {
	eckey := C._goboringcrypto_EC_KEY_new()
	if priv.withKey(func(key *C.GO_EC_KEY) C.int {
		group := C._goboringcrypto_EC_KEY_get0_group(key)
		return C._goboringcrypto_EC_KEY_set_group(eckey, group)
	}) != 1 {
		return nil, NewOpenSSLError("EC_KEY_set_group")
	}
	if C._goboringcrypto_EC_KEY_oct2key(eckey,
		base(pubBytes), C.size_t(len(pubBytes)),
		nil) != 1 {
		return nil, NewOpenSSLError("EC_KEY_oct2key")
	}
	k := &PublicKeyECDSA{eckey}
	// Note: Because of the finalizer, any time k.key is passed to cgo,
	// that call must be followed by a call to runtime.KeepAlive(k),
	// to make sure k is not collected (and finalized) before the cgo
	// call returns.
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func SharedKeyECDH(priv *PrivateKeyECDH, peerPublicKey []byte) ([]byte, error) {
	pkeyOurs := C._goboringcrypto_EVP_PKEY_new()
	if pkeyOurs == nil {
		return nil, NewOpenSSLError("EVP_PKEY_new failed")
	}
	defer C._goboringcrypto_EVP_PKEY_free(pkeyOurs)
	if priv.withKey(func(key *C.GO_EC_KEY) C.int {
		return C._goboringcrypto_EVP_PKEY_set1_EC_KEY(pkeyOurs, key)
	}) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_set1_EC_KEY")
	}

	pub, err := getPeerKey(priv, peerPublicKey)
	if err != nil {
		return nil, err
	}

	pkeyPeers := C._goboringcrypto_EVP_PKEY_new()
	if pkeyPeers == nil {
		return nil, NewOpenSSLError("EVP_PKEY_new failed")
	}
	defer C._goboringcrypto_EVP_PKEY_free(pkeyPeers)
	if pub.withKey(func(key *C.GO_EC_KEY) C.int {
		return C._goboringcrypto_EVP_PKEY_set1_EC_KEY(pkeyPeers, key)
	}) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_set1_EC_KEY")
	}

	ctx := C._goboringcrypto_EVP_PKEY_CTX_new(pkeyOurs, nil)
	if ctx == nil {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_new failed")
	}
	defer C._goboringcrypto_EVP_PKEY_CTX_free(ctx)
	if C._goboringcrypto_EVP_PKEY_derive_init(ctx) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init failed")
	}
	if C._goboringcrypto_EVP_PKEY_derive_set_peer_ex(ctx, pkeyPeers, 1) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_set_peer_ex failed")
	}
	var outLen C.size_t
	if C._goboringcrypto_EVP_PKEY_derive(ctx, nil, &outLen) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init failed")
	}
	out := make([]byte, outLen)
	if C._goboringcrypto_EVP_PKEY_derive(ctx, base(out), &outLen) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init failed")
	}
	return out[:outLen], nil
}
