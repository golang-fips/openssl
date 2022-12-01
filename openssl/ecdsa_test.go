//go:build linux && !android
// +build linux,!android

package openssl_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/golang-fips/openssl-fips/openssl"
	"github.com/golang-fips/openssl-fips/openssl/bbig"
)

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P224", elliptic.P224()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestECDSAKeyGeneration(t *testing.T) {
	testAllCurves(t, testECDSAKeyGeneration)
}

func testECDSAKeyGeneration(t *testing.T, c elliptic.Curve) {
	priv, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func TestECDSASignAndVerify(t *testing.T) {
	testAllCurves(t, testECDSASignAndVerify)
}

func testECDSASignAndVerify(t *testing.T, c elliptic.Curve) {
	key, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := openssl.NewPrivateKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y), bbig.Enc(key.D))
	if err != nil {
		t.Fatal(err)
	}
	hashed := []byte("testing")
	sig, err := openssl.SignMarshalECDSA(priv, hashed)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := openssl.NewPublicKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y))
	if err != nil {
		t.Fatal(err)
	}
	if !openssl.VerifyECDSA(pub, hashed, sig) {
		t.Errorf("Verify failed")
	}
	hashed[0] ^= 0xff
	if openssl.VerifyECDSA(pub, hashed, sig) {
		t.Errorf("Verify succeeded despite intentionally invalid hash!")
	}
}

func generateKeycurve(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	x, y, d, err := openssl.GenerateKeyECDSA(c.Params().Name)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: bbig.Dec(x), Y: bbig.Dec(y)}, D: bbig.Dec(d)}, nil
}
