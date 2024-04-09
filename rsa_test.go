package openssl_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/golang-fips/openssl/v2"
	"github.com/golang-fips/openssl/v2/bbig"
)

func TestRSAKeyGeneration(t *testing.T) {
	for _, size := range []int{2048, 3072} {
		size := size
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			priv, pub := newRSAKey(t, size)
			msg := []byte("hi!")
			enc, err := openssl.EncryptRSAPKCS1(pub, msg)
			if err != nil {
				t.Fatalf("EncryptPKCS1v15: %v", err)
			}
			dec, err := openssl.DecryptRSAPKCS1(priv, enc)
			if err != nil {
				t.Fatalf("DecryptPKCS1v15: %v", err)
			}
			if !bytes.Equal(dec, msg) {
				t.Fatalf("got:%x want:%x", dec, msg)
			}
		})
	}
}

func TestEncryptDecryptOAEP(t *testing.T) {
	sha256 := openssl.NewSHA256()
	msg := []byte("hi!")
	label := []byte("ho!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := openssl.EncryptRSAOAEP(sha256, nil, pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := openssl.DecryptRSAOAEP(sha256, nil, priv, enc, label)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
	sha1 := openssl.NewSHA1()
	_, err = openssl.DecryptRSAOAEP(sha1, nil, priv, enc, label)
	if err == nil {
		t.Error("decrypt failure expected due to hash mismatch")
	}
}

func TestEncryptDecryptOAEP_EmptyLabel(t *testing.T) {
	sha256 := openssl.NewSHA256()
	msg := []byte("hi!")
	label := []byte("")
	priv, pub := newRSAKey(t, 2048)
	enc, err := openssl.EncryptRSAOAEP(sha256, nil, pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := openssl.DecryptRSAOAEP(sha256, nil, priv, enc, label)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
	sha1 := openssl.NewSHA1()
	_, err = openssl.DecryptRSAOAEP(sha1, nil, priv, enc, label)
	if err == nil {
		t.Error("decrypt failure expected due to hash mismatch")
	}
}

func TestEncryptDecryptOAEP_WithMGF1Hash(t *testing.T) {
	sha1 := openssl.NewSHA1()
	sha256 := openssl.NewSHA256()
	msg := []byte("hi!")
	label := []byte("ho!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := openssl.EncryptRSAOAEP(sha256, sha1, pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := openssl.DecryptRSAOAEP(sha256, sha1, priv, enc, label)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
	_, err = openssl.DecryptRSAOAEP(sha256, sha256, priv, enc, label)
	if err == nil {
		t.Error("decrypt failure expected due to mgf1 hash mismatch")
	}
}

func TestEncryptDecryptOAEP_WrongLabel(t *testing.T) {
	sha256 := openssl.NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := openssl.EncryptRSAOAEP(sha256, nil, pub, msg, []byte("ho!"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := openssl.DecryptRSAOAEP(sha256, nil, priv, enc, []byte("wrong!"))
	if err == nil {
		t.Errorf("error expected")
	}
	if dec != nil {
		t.Errorf("got:%x want: nil", dec)
	}
}

func TestSignVerifyPKCS1v15(t *testing.T) {
	sha256 := openssl.NewSHA256()
	priv, pub := newRSAKey(t, 2048)
	msg := []byte("hi!")
	sha256.Write(msg)
	hashed := sha256.Sum(nil)
	signed, err := openssl.SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	signed2, err := openssl.HashSignRSAPKCS1v15(priv, crypto.SHA256, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed, signed2) {
		t.Fatalf("got:%x want:%x", signed, signed2)
	}
	err = openssl.VerifyRSAPKCS1v15(pub, crypto.SHA256, hashed, signed)
	if err != nil {
		t.Fatal(err)
	}
	err = openssl.HashVerifyRSAPKCS1v15(pub, crypto.SHA256, msg, signed2)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyPKCS1v15_Unhashed(t *testing.T) {
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	signed, err := openssl.SignRSAPKCS1v15(priv, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	err = openssl.VerifyRSAPKCS1v15(pub, 0, msg, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyPKCS1v15_Invalid(t *testing.T) {
	sha256 := openssl.NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	sha256.Write(msg)
	hashed := sha256.Sum(nil)
	signed, err := openssl.SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	err = openssl.VerifyRSAPKCS1v15(pub, crypto.SHA256, msg, signed)
	if err == nil {
		t.Fatal("error expected")
	}
}

func TestSignVerifyRSAPSS(t *testing.T) {
	// Test cases taken from
	// https://github.com/golang/go/blob/54182ff54a687272dd7632c3a963e036ce03cb7c/src/crypto/rsa/pss_test.go#L200.
	const keyBits = 2048
	var saltLengthCombinations = []struct {
		signSaltLength, verifySaltLength int
		good                             bool
	}{
		{rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthAuto, true},
		{rsa.PSSSaltLengthEqualsHash, rsa.PSSSaltLengthAuto, true},
		{rsa.PSSSaltLengthEqualsHash, rsa.PSSSaltLengthEqualsHash, true},
		{rsa.PSSSaltLengthEqualsHash, 8, false},
		{rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash, false},
		{8, 8, true},
		{rsa.PSSSaltLengthAuto, keyBits/8 - 2 - 32, true}, // simulate Go PSSSaltLengthAuto algorithm (32 = sha256 size)
		{rsa.PSSSaltLengthAuto, 20, false},
		{rsa.PSSSaltLengthAuto, -2, false},
	}
	sha256 := openssl.NewSHA256()
	priv, pub := newRSAKey(t, keyBits)
	sha256.Write([]byte("testing"))
	hashed := sha256.Sum(nil)
	for i, test := range saltLengthCombinations {
		signed, err := openssl.SignRSAPSS(priv, crypto.SHA256, hashed, test.signSaltLength)
		if err != nil {
			t.Errorf("#%d: error while signing: %s", i, err)
			continue
		}
		err = openssl.VerifyRSAPSS(pub, crypto.SHA256, hashed, signed, test.verifySaltLength)
		if (err == nil) != test.good {
			t.Errorf("#%d: bad result, wanted: %t, got: %s", i, test.good, err)
		}
	}
}

func newRSAKey(t *testing.T, size int) (*openssl.PrivateKeyRSA, *openssl.PublicKeyRSA) {
	t.Helper()
	N, E, D, P, Q, Dp, Dq, Qinv, err := openssl.GenerateKeyRSA(size)
	if err != nil {
		t.Fatalf("GenerateKeyRSA(%d): %v", size, err)
	}
	// Exercise omission of precomputed value
	Dp = nil
	priv, err := openssl.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		t.Fatalf("NewPrivateKeyRSA(%d): %v", size, err)
	}
	pub, err := openssl.NewPublicKeyRSA(N, E)
	if err != nil {
		t.Fatalf("NewPublicKeyRSA(%d): %v", size, err)
	}
	return priv, pub
}

func fromBase36(base36 string) *big.Int {
	i, ok := new(big.Int).SetString(base36, 36)
	if !ok {
		panic("bad number: " + base36)
	}
	return i
}

func BenchmarkEncryptRSAPKCS1(b *testing.B) {
	b.StopTimer()
	// Public key length should be at least of 2048 bits, else OpenSSL will report an error when running in FIPS mode.
	n := fromBase36("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557")
	test2048PubKey, err := openssl.NewPublicKeyRSA(bbig.Enc(n), bbig.Enc(big.NewInt(3)))
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := openssl.EncryptRSAPKCS1(test2048PubKey, []byte("testing")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateKeyRSA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _, _, _, err := openssl.GenerateKeyRSA(2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestOverlongMessagePKCS1v15(t *testing.T) {
	priv := parseKey(rsaPrivateKey)
	ciphertext := decodeBase64("fjOVdirUzFoLlukv80dBllMLjXythIf22feqPrNo0YoIjzyzyoMFiLjAc/Y4krkeZ11XFThIrEvw\nkRiZcCq5ng==")
	_, err := openssl.DecryptRSAPKCS1(priv, ciphertext)
	if err == nil {
		t.Error("RSA decrypted a message that was too long.")
	}
}

var rsaPrivateKey = testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END RSA TESTING KEY-----`)

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func parseKey(s string) *openssl.PrivateKeyRSA {
	p, _ := pem.Decode([]byte(s))
	var err error
	k, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}
	key, err := openssl.NewPrivateKeyRSA(bbig.Enc(k.N), bbig.Enc(big.NewInt(int64(k.E))), bbig.Enc(k.D), bbig.Enc(k.Primes[0]), bbig.Enc(k.Primes[1]), nil, nil, nil)
	if err != nil {
		panic(err)
	}
	return key
}
