package openssl_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

func TestNewKeyFromSeedEd25519(t *testing.T) {
	if !openssl.SupportsEd25519() {
		t.Skip("Ed25519 not supported")
	}
	seed := bytes.Repeat([]byte{0x01}, ed25519.SeedSize)
	priv, err := openssl.NewKeyFromSeedEd25519(seed)
	if err != nil {
		t.Fatal(err)
	}
	priv2 := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(priv, priv2) {
		t.Errorf("private key mismatch")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	if !openssl.SupportsEd25519() {
		t.Skip("Ed25519 not supported")
	}
	public, private, err := openssl.GenerateKeyEd25519()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("test message")
	sig, err := openssl.SignEd25519(private, message)
	if err != nil {
		t.Fatal(err)
	}
	if sig2 := ed25519.Sign(private, message); !bytes.Equal(sig, sig2) {
		t.Errorf("signature mismatch")
	}
	if openssl.VerifyEd25519(public, message, sig) != nil {
		t.Errorf("valid signature rejected")
	}
	wrongMessage := []byte("wrong message")
	if openssl.VerifyEd25519(public, wrongMessage, sig) == nil {
		t.Errorf("signature of different message accepted")
	}
}

func TestEd25519SignVerifyHashed(t *testing.T) {
	if !openssl.SupportsEd25519ph() {
		t.Skip("Ed25519ph not supported")
	}
	// From RFC 8032, Section 7.3
	key, _ := hex.DecodeString("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
	expectedSig, _ := hex.DecodeString("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")
	message, _ := hex.DecodeString("616263")

	private := ed25519.PrivateKey(key)
	public := []byte(private.Public().(ed25519.PublicKey))
	hash := sha512.Sum512(message)
	sig, err := openssl.SignEd25519ph(key, hash[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Error("signature doesn't match test vector")
	}

	if err := openssl.VerifyEd25519ph(public, hash[:], sig, nil); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	wrongHash := sha512.Sum512([]byte("wrong message"))
	if openssl.VerifyEd25519ph(public, wrongHash[:], sig, nil) == nil {
		t.Errorf("signature of different message accepted")
	}

	sig[0] ^= 0xff
	if openssl.VerifyEd25519ph(public, hash[:], sig, nil) == nil {
		t.Errorf("invalid signature accepted")
	}
	sig[0] ^= 0xff
	sig[ed25519.SignatureSize-1] ^= 0xff
	if openssl.VerifyEd25519ph(public, hash[:], sig, nil) == nil {
		t.Errorf("invalid signature accepted")
	}

	// The RFC provides no test vectors for Ed25519ph with context, so just sign
	// and verify something.
	sig, err = openssl.SignEd25519ph(key, hash[:], []byte("123"))
	if err != nil {
		t.Fatal(err)
	}
	if err := openssl.VerifyEd25519ph(public, hash[:], sig, []byte("123")); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	if err := openssl.VerifyEd25519ph(public, hash[:], sig, []byte("321")); err == nil {
		t.Errorf("expected error for wrong context")
	}
}

func TestEd25519SignVerifyContext(t *testing.T) {
	if !openssl.SupportsEd25519ctx() {
		t.Skip("Ed25519ctx not supported")
	}
	// From RFC 8032, Section 7.2
	key, _ := hex.DecodeString("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292")
	expectedSig, _ := hex.DecodeString("55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d")
	message, _ := hex.DecodeString("f726936d19c800494e3fdaff20b276a8")
	context := []byte("foo")

	private := ed25519.PrivateKey(key)
	public := []byte(private.Public().(ed25519.PublicKey))
	sig, err := openssl.SignEd25519ctx(key, message, context)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expectedSig) {
		t.Error("signature doesn't match test vector")
	}

	if err := openssl.VerifyEd25519ctx(public, message, sig, context); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	if openssl.VerifyEd25519ctx(public, []byte("bar"), sig, context) == nil {
		t.Errorf("signature of different message accepted")
	}
	if openssl.VerifyEd25519ctx(public, message, sig, []byte("bar")) == nil {
		t.Errorf("signature with different context accepted")
	}

	sig[0] ^= 0xff
	if openssl.VerifyEd25519ctx(public, message, sig, context) == nil {
		t.Errorf("invalid signature accepted")
	}
	sig[0] ^= 0xff
	sig[ed25519.SignatureSize-1] ^= 0xff
	if openssl.VerifyEd25519ctx(public, message, sig, context) == nil {
		t.Errorf("invalid signature accepted")
	}
}

func TestEd25519Malleability(t *testing.T) {
	if !openssl.SupportsEd25519() {
		t.Skip("Ed25519 not supported")
	}
	// https://tools.ietf.org/html/rfc8032#section-5.1.7 adds an additional test
	// that s be in [0, order). This prevents someone from adding a multiple of
	// order to s and obtaining a second valid signature for the same message.
	msg := []byte{0x54, 0x65, 0x73, 0x74}
	sig := []byte{
		0x7c, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a,
		0x0f, 0x2d, 0xb8, 0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b,
		0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a, 0x27, 0x77, 0x4a, 0xb0, 0x67,
		0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d,
		0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33,
		0x36, 0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
	}
	publicKey := []byte{
		0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5,
		0x22, 0xab, 0xbe, 0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34,
		0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa,
	}

	if openssl.VerifyEd25519(publicKey, msg, sig) == nil {
		t.Fatal("non-canonical signature accepted")
	}
}

func BenchmarkEd25519GenerateKey(b *testing.B) {
	if !openssl.SupportsEd25519() {
		b.Skip("Ed25519 not supported")
	}
	for i := 0; i < b.N; i++ {
		_, _, err := openssl.GenerateKeyEd25519()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519NewKeyFromSeed(b *testing.B) {
	if !openssl.SupportsEd25519() {
		b.Skip("Ed25519 not supported")
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := 0; i < b.N; i++ {
		_, err := openssl.NewKeyFromSeedEd25519(seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519Signing(b *testing.B) {
	if !openssl.SupportsEd25519() {
		b.Skip("Ed25519 not supported")
	}
	_, priv, err := openssl.GenerateKeyEd25519()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		openssl.SignEd25519(priv, message)
	}
}

func BenchmarkEd25519Verification(b *testing.B) {
	if !openssl.SupportsEd25519() {
		b.Skip("Ed25519 not supported")
	}
	pub, priv, err := openssl.GenerateKeyEd25519()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, err := openssl.SignEd25519(priv, message)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		openssl.VerifyEd25519(pub, message, signature)
	}
}
