package openssl_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/golang-fips/openssl/v2"
	"github.com/golang-fips/openssl/v2/bbig"
)

func TestRSAKeyGeneration(t *testing.T) {
	for _, size := range []int{2048, 3072} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			_, _, _, _, _, _, _, _, err := openssl.GenerateKeyRSA(size)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testRSAEncryptDecryptPKCS1(t *testing.T, priv *openssl.PrivateKeyRSA, pub *openssl.PublicKeyRSA) {
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
}

func TestRSAEncryptDecryptPKCS1(t *testing.T) {
	if !openssl.SupportsRSAPKCS1v15Encryption() {
		t.Skip("RSA PKCS1 v1.5 encryption not supported")
	}
	for _, size := range []int{2048, 3072} {
		size := size
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			priv, pub := newRSAKey(t, size)
			testRSAEncryptDecryptPKCS1(t, priv, pub)
		})
	}
}

func TestRSAEncryptDecryptPKCS1_MissingPrecomputedValues(t *testing.T) {
	if !openssl.SupportsRSAPKCS1v15Encryption() {
		t.Skip("RSA PKCS1 v1.5 encryption not supported")
	}
	n, e, d, p, q, dp, dq, qinv, err := openssl.GenerateKeyRSA(2048)
	if err != nil {
		t.Fatalf("GenerateKeyRSA: %v", err)
	}
	tt := []struct {
		withDp   bool
		withDq   bool
		withQinv bool
	}{
		{true, true, false},
		{true, false, true},
		{false, true, true},
		{false, false, false},
		{false, false, true},
		{false, true, false},
		{true, false, false},
		{true, true, true},
	}
	for _, tt := range tt {
		tt := tt
		t.Run(fmt.Sprintf("dp=%v,dq=%v,qinv=%v", tt.withDp, tt.withDq, tt.withQinv), func(t *testing.T) {
			t.Parallel()
			dp1, dq1, qinv1 := dp, dq, qinv
			if !tt.withDp {
				dp1 = nil
			}
			if !tt.withDq {
				dq1 = nil
			}
			if !tt.withQinv {
				qinv1 = nil
			}

			priv, pub := newRSAKeyFromParams(t, n, e, d, p, q, dp1, dq1, qinv1)
			testRSAEncryptDecryptPKCS1(t, priv, pub)
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

func TestRSAEncryptDecryptOAEP(t *testing.T) {
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

func TestRSAEncryptDecryptOAEP_EmptyLabel(t *testing.T) {
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

func TestRSAEncryptDecryptOAEP_WithMGF1Hash(t *testing.T) {
	if symCryptProviderAvailable() {
		t.Skip("SymCrypt provider does not support MGF1 hash")
	}

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

func TestRSAEncryptDecryptOAEP_WrongLabel(t *testing.T) {
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

// These are all the hashes supported by Go's crypto/rsa package
// as of Go 1.24.
var stdHashes = [...]crypto.Hash{
	crypto.MD5SHA1,
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA512,
	crypto.SHA512_224,
	crypto.SHA512_256,
	crypto.SHA3_224,
	crypto.SHA3_256,
	crypto.SHA3_512,
	crypto.RIPEMD160,
}

func TestRSAHashSignVerifyPKCS1v15(t *testing.T) {
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

func TestRSASignVerifyPKCS1v15_Invalid(t *testing.T) {
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

func TestRSASignVerifyRSAPSS_SaltLength(t *testing.T) {
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
	return newRSAKeyFromParams(t, N, E, D, P, Q, Dp, Dq, Qinv)
}

func newRSAKeyFromParams(t *testing.T, N, E, D, P, Q, Dp, Dq, Qinv openssl.BigInt) (*openssl.PrivateKeyRSA, *openssl.PublicKeyRSA) {
	t.Helper()
	priv, err := openssl.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		t.Fatalf("NewPrivateKeyRSA: %v", err)
	}
	pub, err := openssl.NewPublicKeyRSA(N, E)
	if err != nil {
		t.Fatalf("NewPublicKeyRSA: %v", err)
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

func BenchmarkEncryptRSA(b *testing.B) {
	b.StopTimer()
	// Public key length should be at least of 2048 bits, else OpenSSL will report an error when running in FIPS mode.
	n := fromBase36("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557")
	test2048PubKey, err := openssl.NewPublicKeyRSA(bbig.Enc(n), bbig.Enc(big.NewInt(3)))
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	b.Run("PKCS1", func(b *testing.B) {
		if !openssl.SupportsRSAPKCS1v15Encryption() {
			b.Skip("RSA PKCS1 v1.5 encryption not supported")
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := openssl.EncryptRSAPKCS1(test2048PubKey, []byte("testing")); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("OAEP", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := openssl.EncryptRSAOAEP(openssl.NewSHA256(), nil, test2048PubKey, []byte("testing"), nil); err != nil {
				b.Fatal(err)
			}
		}
	})
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

func TestRSAPSS(t *testing.T) {
	privGo, err := rsa.GenerateKey(openssl.RandReader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := openssl.NewPrivateKeyRSA(
		bbig.Enc(privGo.N), bbig.Enc(big.NewInt(int64(privGo.E))), bbig.Enc(privGo.D),
		bbig.Enc(privGo.Primes[0]), bbig.Enc(privGo.Primes[1]), nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := openssl.NewPublicKeyRSA(bbig.Enc(privGo.N), bbig.Enc(big.NewInt(int64(privGo.E))))
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range stdHashes {
		t.Run(hash.String(), func(t *testing.T) {
			if !openssl.SupportsRSAPSS(hash) {
				t.Skipf("Hash %v not supported", hash)
			}
			digest := make([]byte, hash.Size())
			digest[0] = 0x30
			signature, err := openssl.SignRSAPSS(priv, hash, digest, rsa.PSSSaltLengthEqualsHash)
			if err != nil {
				t.Fatal(err)
			}
			if len(signature) == 0 {
				t.Fatal("empty signature returned")
			}
			err = openssl.VerifyRSAPSS(pub, hash, digest, signature, rsa.PSSSaltLengthEqualsHash)
			if err != nil {
				t.Error(err)
			}
			if hash.Available() {
				// Verify with crypto/rsa
				err = rsa.VerifyPSS(&privGo.PublicKey, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestRSAPKCS1Signature(t *testing.T) {
	privGo, err := rsa.GenerateKey(openssl.RandReader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := openssl.NewPrivateKeyRSA(
		bbig.Enc(privGo.N), bbig.Enc(big.NewInt(int64(privGo.E))), bbig.Enc(privGo.D),
		bbig.Enc(privGo.Primes[0]), bbig.Enc(privGo.Primes[1]), nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := openssl.NewPublicKeyRSA(bbig.Enc(privGo.N), bbig.Enc(big.NewInt(int64(privGo.E))))
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range append([]crypto.Hash{0}, stdHashes[:]...) {
		t.Run(hash.String(), func(t *testing.T) {
			if !openssl.SupportsRSAPKCS1v15Signature(hash) {
				t.Skipf("Hash %v not supported", hash)
			}
			// Construct a fake hashed data.
			size := 1
			if hash != 0 {
				size = hash.Size()
			}
			digest := make([]byte, size)
			digest[0] = 0x30
			signature, err := openssl.SignRSAPKCS1v15(priv, hash, digest)
			if err != nil {
				t.Fatal(err)
			}
			if len(signature) == 0 {
				t.Fatal("empty signature returned")
			}
			err = openssl.VerifyRSAPKCS1v15(pub, hash, digest, signature)
			if err != nil {
				t.Error(err)
			}
			if hash.Available() {
				// Verify with crypto/rsa
				err = rsa.VerifyPKCS1v15(&privGo.PublicKey, hash, digest, signature)
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestRSAOAEP(t *testing.T) {
	privGo, err := rsa.GenerateKey(openssl.RandReader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := openssl.NewPrivateKeyRSA(
		bbig.Enc(privGo.N), bbig.Enc(big.NewInt(int64(privGo.E))), bbig.Enc(privGo.D),
		bbig.Enc(privGo.Primes[0]), bbig.Enc(privGo.Primes[1]), nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := openssl.NewPublicKeyRSA(bbig.Enc(privGo.N), bbig.Enc(big.NewInt(int64(privGo.E))))
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range hashes {
		t.Run(hash.String(), func(t *testing.T) {
			if !openssl.SupportsHash(hash) {
				t.Skipf("Hash %v not supported", hash)
			}
			h := cryptoToHash(hash)()
			if !openssl.SupportsRSAOAEP(h, h) {
				t.Skipf("Hash %v not supported", hash)
			}
			msg := []byte("hi!")
			label := []byte("ho!")
			ciphertext, err := openssl.EncryptRSAOAEP(h, h, pub, msg, label)
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) == 0 {
				t.Fatal("empty ciphertext returned")
			}
			plaintext, err := openssl.DecryptRSAOAEP(h, h, priv, ciphertext, label)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(plaintext, msg) {
				t.Errorf("got:%x want:%x", plaintext, msg)
			}
			if hash.Available() {
				// Decrypt with crypto/rsa
				plaintext, err = rsa.DecryptOAEP(h, openssl.RandReader, privGo, ciphertext, label)
				if err != nil {
					t.Error(err)
				}
				if !bytes.Equal(plaintext, msg) {
					t.Errorf("got:%x want:%x", plaintext, msg)
				}
			}
		})
	}
}

func TestSupportsRSAOAEP(t *testing.T) {
	// Test only applies when SymCrypt provider is used,
	// as we know which hashes are supported there.
	if !symCryptProviderAvailable() {
		t.Skip("SymCrypt provider not available")
	}
	for _, ch := range []crypto.Hash{
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_512,
	} {
		t.Run(ch.String(), func(t *testing.T) {
			h := cryptoToHash(ch)()
			if !openssl.SupportsRSAOAEP(h, h) {
				t.Errorf("SupportsRSAOAEP(%v, %v) = false, want true", ch, ch)
			}
		})
	}
}

func TestSupportsRSAPKCS1v15Encryption(t *testing.T) {
	// Test only applies when SymCrypt provider is used,
	// as we know which hashes are supported there.
	if !symCryptProviderAvailable() {
		t.Skip("SymCrypt provider not available")
	}
	if !openssl.SupportsRSAPKCS1v15Encryption() {
		t.Errorf("SupportsRSAPKCS1v15Encryption() = false, want true")
	}
}

func TestSupportsRSAPKCS1v15Signature(t *testing.T) {
	// Test only applies when SymCrypt provider is used,
	// as we know which hashes are supported there.
	if !symCryptProviderAvailable() {
		t.Skip("SymCrypt provider not available")
	}
	for _, ch := range []crypto.Hash{
		0,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_512,
	} {
		t.Run(ch.String(), func(t *testing.T) {
			if !openssl.SupportsRSAPKCS1v15Signature(ch) {
				t.Errorf("SupportsRSAPKCS1v15Signature(%v) = false, want true", ch)
			}
		})
	}
}

func TestSupportsRSAPSS(t *testing.T) {
	// Test only applies when SymCrypt provider is used,
	// as we know which hashes are supported there.
	if !symCryptProviderAvailable() {
		t.Skip("SymCrypt provider not available")
	}
	for _, ch := range []crypto.Hash{
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_512,
	} {
		t.Run(ch.String(), func(t *testing.T) {
			if !openssl.SupportsRSAPSS(ch) {
				t.Errorf("SupportsRSAPSS(%v) = false, want true", ch)
			}
		})
	}
}
