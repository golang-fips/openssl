// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux || !cgo || android || cmd_go_bootstrap || msan || no_openssl
// +build !linux !cgo android cmd_go_bootstrap msan no_openssl

package openssl

import (
	"crypto"
	"crypto/cipher"
	"hash"
	"io"
)

var enabled = false

// Unreachable marks code that should be unreachable
// when BoringCrypto is in use. It is a no-op without BoringCrypto.
func Unreachable() {
}

// UnreachableExceptTests marks code that should be unreachable
// when BoringCrypto is in use. It is a no-op without BoringCrypto.
func UnreachableExceptTests() {}

func ExecutingTest() bool { return false }

// This is a noop withotu BoringCrytpo.
func PanicIfStrictFIPS(v interface{}) {}

type randReader int

func (randReader) Read(b []byte) (int, error) { panic("boringcrypto: not available") }

const RandReader = randReader(0)

func NewSHA1() hash.Hash   { panic("boringcrypto: not available") }
func NewSHA224() hash.Hash { panic("boringcrypto: not available") }
func NewSHA256() hash.Hash { panic("boringcrypto: not available") }
func NewSHA384() hash.Hash { panic("boringcrypto: not available") }
func NewSHA512() hash.Hash { panic("boringcrypto: not available") }

func NewHMAC(h func() hash.Hash, key []byte) hash.Hash { panic("boringcrypto: not available") }

func NewAESCipher(key []byte) (cipher.Block, error) { panic("boringcrypto: not available") }

type PublicKeyECDSA struct{ _ int }
type PrivateKeyECDSA struct{ _ int }

func GenerateKeyECDSA(curve string) (X, Y, D BigInt, err error) {
	panic("boringcrypto: not available")
}
func NewPrivateKeyECDSA(curve string, X, Y, D BigInt) (*PrivateKeyECDSA, error) {
	panic("boringcrypto: not available")
}
func NewPublicKeyECDSA(curve string, X, Y BigInt) (*PublicKeyECDSA, error) {
	panic("boringcrypto: not available")
}
func SignECDSA(priv *PrivateKeyECDSA, hash []byte, h crypto.Hash) (r, s BigInt, err error) {
	panic("boringcrypto: not available")
}
func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte, h crypto.Hash) ([]byte, error) {
	panic("boringcrypto: not available")
}
func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, r, s BigInt, h crypto.Hash) bool {
	panic("boringcrypto: not available")
}

type PublicKeyECDH struct{ _ int }
type PrivateKeyECDH struct{ _ int }

func (pc *PublicKeyECDH) Bytes() []byte { panic("boringcrypto: not available") }
func (pc *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) { panic("boringcrypto: not available") }

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	panic("boringcrypto: not available")
}
func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	panic("boringcrypto: not available")
}
func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	panic("boringcrypto: not available")
}
func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	panic("boringcrypto: not available")
}

type PublicKeyRSA struct{ _ int }
type PrivateKeyRSA struct{ _ int }

func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}
func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	panic("boringcrypto: not available")
}
func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error) {
	panic("boringcrypto: not available")
}
func NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error) { panic("boringcrypto: not available") }
func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, msgHashed bool) ([]byte, error) {
	panic("boringcrypto: not available")
}
func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	panic("boringcrypto: not available")
}
func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, msgHashed bool) error {
	panic("boringcrypto: not available")
}
func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	panic("boringcrypto: not available")
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	panic("boringcrypto: not available")
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	panic("boringcrypto: not available")
}
