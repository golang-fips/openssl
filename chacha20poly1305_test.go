// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openssl_test

import (
	"bytes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/hex"
	mathrand "math/rand/v2"
	"strconv"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

const (
	nonceSize  = 12
	nonceSizeX = 24
)

func TestChacha20Poly1305Vectors(t *testing.T) {
	if !openssl.SupportsChaCha20Poly1305() {
		t.Skip("ChaCha20-Poly1305 not supported")
	}
	for i, test := range chacha20Poly1305Tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			key, _ := hex.DecodeString(test.key)
			nonce, _ := hex.DecodeString(test.nonce)
			ad, _ := hex.DecodeString(test.aad)
			plaintext, _ := hex.DecodeString(test.plaintext)

			var (
				aead cipher.AEAD
				err  error
			)
			switch len(nonce) {
			case nonceSize:
				aead, err = openssl.NewChaCha20Poly1305(key)
			case nonceSizeX:
				t.Skip("SizeX not supported")
			default:
				t.Fatalf("#%d: wrong nonce length: %d", i, len(nonce))
			}
			if err != nil {
				t.Fatal(err)
			}

			ct := aead.Seal(nil, nonce, plaintext, ad)
			if ctHex := hex.EncodeToString(ct); ctHex != test.out {
				t.Fatalf("#%d: got %s, want %s", i, ctHex, test.out)
			}

			plaintext2, err := aead.Open(nil, nonce, ct, ad)
			if err != nil {
				t.Fatalf("#%d: Open failed", i)
			}

			if !bytes.Equal(plaintext, plaintext2) {
				t.Fatalf("#%d: plaintext's don't match: got %x vs %x", i, plaintext2, plaintext)
			}

			if len(ad) > 0 {
				alterAdIdx := mathrand.N(len(ad))
				ad[alterAdIdx] ^= 0x80
				if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
					t.Errorf("#%d: Open was successful after altering additional data", i)
				}
				ad[alterAdIdx] ^= 0x80
			}

			alterNonceIdx := mathrand.N(aead.NonceSize())
			nonce[alterNonceIdx] ^= 0x80
			if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
				t.Errorf("#%d: Open was successful after altering nonce", i)
			}
			nonce[alterNonceIdx] ^= 0x80

			alterCtIdx := mathrand.N(len(ct))
			ct[alterCtIdx] ^= 0x80
			if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
				t.Errorf("#%d: Open was successful after altering ciphertext", i)
			}
			ct[alterCtIdx] ^= 0x80
		})
	}
}

func TestChaCha20Poly1305Random(t *testing.T) {
	if !openssl.SupportsChaCha20Poly1305() {
		t.Skip("ChaCha20-Poly1305 not supported")
	}
	// Some random tests to verify Open(Seal) == Plaintext
	f := func(t *testing.T, nonceSize int) {
		for i := 0; i < 256; i++ {
			var nonce = make([]byte, nonceSize)
			var key [32]byte

			al := mathrand.N(128)
			pl := mathrand.N(16384)
			ad := make([]byte, al)
			plaintext := make([]byte, pl)
			cryptorand.Read(key[:])
			cryptorand.Read(nonce[:])
			cryptorand.Read(ad)
			cryptorand.Read(plaintext)

			var (
				aead cipher.AEAD
				err  error
			)
			switch len(nonce) {
			case nonceSize:
				aead, err = openssl.NewChaCha20Poly1305(key[:])
			case nonceSizeX:
				t.Skip("SizeX not supported")
			default:
				t.Fatalf("#%d: wrong nonce length: %d", i, len(nonce))
			}
			if err != nil {
				t.Fatal(err)
			}

			ct := aead.Seal(nil, nonce[:], plaintext, ad)

			plaintext2, err := aead.Open(nil, nonce[:], ct, ad)
			if err != nil {
				t.Errorf("Random #%d: Open failed", i)
				continue
			}

			if !bytes.Equal(plaintext, plaintext2) {
				t.Errorf("Random #%d: plaintext's don't match: got %x vs %x", i, plaintext2, plaintext)
				continue
			}

			if len(ad) > 0 {
				alterAdIdx := mathrand.N(len(ad))
				ad[alterAdIdx] ^= 0x80
				if _, err := aead.Open(nil, nonce[:], ct, ad); err == nil {
					t.Errorf("Random #%d: Open was successful after altering additional data", i)
				}
				ad[alterAdIdx] ^= 0x80
			}

			alterNonceIdx := mathrand.N(aead.NonceSize())
			nonce[alterNonceIdx] ^= 0x80
			if _, err := aead.Open(nil, nonce[:], ct, ad); err == nil {
				t.Errorf("Random #%d: Open was successful after altering nonce", i)
			}
			nonce[alterNonceIdx] ^= 0x80

			alterCtIdx := mathrand.N(len(ct))
			ct[alterCtIdx] ^= 0x80
			if _, err := aead.Open(nil, nonce[:], ct, ad); err == nil {
				t.Errorf("Random #%d: Open was successful after altering ciphertext", i)
			}
			ct[alterCtIdx] ^= 0x80
		}
	}
	t.Run("Standard", func(t *testing.T) { f(t, 12) })
}

func benchmarkChaCha20Poly1305Seal(b *testing.B, buf []byte, nLen int) {
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var nonce = make([]byte, nLen)
	var ad [13]byte
	var out []byte

	var aead cipher.AEAD
	switch len(nonce) {
	case nonceSize:
		aead, _ = openssl.NewChaCha20Poly1305(key[:])
	case nonceSizeX:
		b.Skip("SizeX not supported")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aead.Seal(out[:0], nonce[:], buf[:], ad[:])
	}
}

func benchmarkChaCha20Poly1305Open(b *testing.B, buf []byte, nLen int) {
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var nonce = make([]byte, nLen)
	var ad [13]byte
	var ct []byte
	var out []byte

	var aead cipher.AEAD
	switch len(nonce) {
	case nonceSize:
		aead, _ = openssl.NewChaCha20Poly1305(key[:])
	case nonceSizeX:
		b.Skip("SizeX not supported")
	}
	ct = aead.Seal(ct[:0], nonce[:], buf[:], ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ = aead.Open(out[:0], nonce[:], ct[:], ad[:])
	}
}

func BenchmarkChacha20Poly1305(b *testing.B) {
	if !openssl.SupportsChaCha20Poly1305() {
		b.Skip("ChaCha20-Poly1305 not supported")
	}
	for _, length := range []int{64, 1350, 8 * 1024} {
		b.Run("Open-"+strconv.Itoa(length), func(b *testing.B) {
			benchmarkChaCha20Poly1305Open(b, make([]byte, length), nonceSize)
		})
		b.Run("Seal-"+strconv.Itoa(length), func(b *testing.B) {
			benchmarkChaCha20Poly1305Seal(b, make([]byte, length), nonceSize)
		})

		b.Run("Open-"+strconv.Itoa(length)+"-X", func(b *testing.B) {
			benchmarkChaCha20Poly1305Open(b, make([]byte, length), nonceSizeX)
		})
		b.Run("Seal-"+strconv.Itoa(length)+"-X", func(b *testing.B) {
			benchmarkChaCha20Poly1305Seal(b, make([]byte, length), nonceSizeX)
		})
	}
}
