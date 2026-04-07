package openssl_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"io"
	"math/rand"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

// testShakes contains functions that return *sha3.SHAKE instances for
// with output-length equal to the KAT length.
var testShakes = map[string]struct {
	constructor  func(N []byte, S []byte) *openssl.SHAKE
	defAlgoName  string
	defCustomStr string
}{
	// NewCSHAKE without customization produces same result as SHAKE
	"SHAKE128":  {openssl.NewCSHAKE128, "", ""},
	"SHAKE256":  {openssl.NewCSHAKE256, "", ""},
	"CSHAKE128": {openssl.NewCSHAKE128, "CSHAKE128", "CustomString"},
	"CSHAKE256": {openssl.NewCSHAKE256, "CSHAKE256", "CustomString"},
}

func skipCSHAKEIfNotSupported(t *testing.T, algo string) {
	t.Helper()
	var supported bool
	switch algo {
	case "SHAKE128":
		supported = openssl.SupportsSHAKE(128)
	case "SHAKE256":
		supported = openssl.SupportsSHAKE(256)
	case "CSHAKE128":
		supported = openssl.SupportsCSHAKE(128)
	case "CSHAKE256":
		supported = openssl.SupportsCSHAKE(256)
	}
	if !supported {
		t.Skip("skipping: not supported")
	}
}

func TestSupportsShake(t *testing.T) {
	if !symCryptProviderAvailable() {
		// We only know for sure that SymCrypt supports SHAKE.
		t.Skip("SymCrypt provider not available")
	}
	if !openssl.SupportsSHAKE(128) {
		t.Error("expected SHAKE128 to be supported")
	}
	if !openssl.SupportsSHAKE(256) {
		t.Error("expected SHAKE256 to be supported")
	}
}

// TestCSHAKESqueezing checks that squeezing the full output a single time produces
// the same output as repeatedly squeezing the instance.
func TestCSHAKESqueezing(t *testing.T) {
	const testString = "brekeccakkeccak koax koax"
	for algo, v := range testShakes {
		t.Run(algo, func(t *testing.T) {
			skipCSHAKEIfNotSupported(t, algo)

			d0 := v.constructor([]byte(v.defAlgoName), []byte(v.defCustomStr))
			d0.Write([]byte(testString))
			ref := make([]byte, 32)
			d0.Read(ref)

			d1 := v.constructor([]byte(v.defAlgoName), []byte(v.defCustomStr))
			d1.Write([]byte(testString))
			var multiple []byte
			for range ref {
				d1.Read(make([]byte, 0))
				one := make([]byte, 1)
				d1.Read(one)
				multiple = append(multiple, one...)
			}
			if !bytes.Equal(ref, multiple) {
				t.Errorf("%s: squeezing %d bytes one at a time failed", algo, len(ref))
			}
		})
	}
}

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
//
// The alignment of each slice is intentionally randomized to detect alignment
// issues in the implementation. See https://golang.org/issue/37644.
func sequentialBytes(size int) []byte {
	alignmentOffset := rand.Intn(8)
	result := make([]byte, size+alignmentOffset)[alignmentOffset:]
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

func TestCSHAKEReset(t *testing.T) {
	out1 := make([]byte, 32)
	out2 := make([]byte, 32)

	for algo, v := range testShakes {
		t.Run(algo, func(t *testing.T) {
			skipCSHAKEIfNotSupported(t, algo)

			// Calculate hash for the first time
			c := v.constructor(nil, []byte(v.defCustomStr))
			c.Write(sequentialBytes(0x100))
			c.Read(out1)

			// Calculate hash again
			c.Reset()
			c.Write(sequentialBytes(0x100))
			c.Read(out2)

			if !bytes.Equal(out1, out2) {
				t.Error("\nExpected:\n", out1, "\ngot:\n", out2)
			}
		})
	}
}

func TestCSHAKEAccumulated(t *testing.T) {
	t.Run("CSHAKE128", func(t *testing.T) {
		if !openssl.SupportsCSHAKE(128) {
			t.Skip("skipping: not supported")
		}
		testCSHAKEAccumulated(t, openssl.NewCSHAKE128, (1600-256)/8,
			"bb14f8657c6ec5403d0b0e2ef3d3393497e9d3b1a9a9e8e6c81dbaa5fd809252")
	})
	t.Run("CSHAKE256", func(t *testing.T) {
		if !openssl.SupportsCSHAKE(256) {
			t.Skip("skipping: not supported")
		}
		testCSHAKEAccumulated(t, openssl.NewCSHAKE256, (1600-512)/8,
			"0baaf9250c6e25f0c14ea5c7f9bfde54c8a922c8276437db28f3895bdf6eeeef")
	})
}

func testCSHAKEAccumulated(t *testing.T, newCSHAKE func(N, S []byte) *openssl.SHAKE, rate int64, exp string) {
	rnd := newCSHAKE(nil, nil)
	acc := newCSHAKE(nil, nil)
	for n := 0; n < 200; n++ {
		N := make([]byte, n)
		rnd.Read(N)
		for s := 0; s < 200; s++ {
			S := make([]byte, s)
			rnd.Read(S)

			c := newCSHAKE(N, S)
			io.CopyN(c, rnd, 100 /* < rate */)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, rate)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, 200 /* > rate */)
			io.CopyN(acc, c, 200)
		}
	}
	out := make([]byte, 32)
	acc.Read(out)
	if got := hex.EncodeToString(out); got != exp {
		t.Errorf("got %s, want %s", got, exp)
	}
}

func TestCSHAKELargeS(t *testing.T) {
	if !openssl.SupportsCSHAKE(128) {
		t.Skip("skipping: not supported")
	}
	const s = (1<<32)/8 + 1000 // s * 8 > 2^32
	S := make([]byte, s)
	rnd := openssl.NewSHAKE128()
	rnd.Read(S)
	c := openssl.NewCSHAKE128(nil, S)
	io.CopyN(c, rnd, 1000)
	out := make([]byte, 32)
	c.Read(out)

	exp := "2cb9f237767e98f2614b8779cf096a52da9b3a849280bbddec820771ae529cf0"
	if got := hex.EncodeToString(out); got != exp {
		t.Errorf("got %s, want %s", got, exp)
	}
}

func TestCSHAKESum(t *testing.T) {
	const testString = "hello world"
	t.Run("SHAKE128", func(t *testing.T) {
		if !openssl.SupportsSHAKE(128) {
			t.Skip("skipping: not supported")
		}
		h := openssl.NewSHAKE128()
		h.Write([]byte(testString[:5]))
		h.Write([]byte(testString[5:]))
		want := make([]byte, 32)
		h.Read(want)
		got := openssl.SumSHAKE128([]byte(testString), 32)
		if !bytes.Equal(got, want) {
			t.Errorf("got:%x want:%x", got, want)
		}
	})
	t.Run("SHAKE256", func(t *testing.T) {
		if !openssl.SupportsSHAKE(256) {
			t.Skip("skipping: not supported")
		}
		h := openssl.NewSHAKE256()
		h.Write([]byte(testString[:5]))
		h.Write([]byte(testString[5:]))
		want := make([]byte, 32)
		h.Read(want)
		got := openssl.SumSHAKE256([]byte(testString), 32)
		if !bytes.Equal(got, want) {
			t.Errorf("got:%x want:%x", got, want)
		}
	})
}

// benchmarkHash tests the speed to hash num buffers of buflen each.
func benchmarkHash(b *testing.B, hType crypto.Hash, hfun func() *openssl.Hash, size, num int) {
	if !openssl.SupportsHash(hType) {
		b.Skip("skipping: not supported")
	}
	h := hfun()
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	b.SetBytes(int64(size * num))
	b.StartTimer()

	var state []byte
	for i := 0; i < b.N; i++ {
		for j := 0; j < num; j++ {
			h.Write(data)
		}
		state = h.Sum(state[:0])
	}
	b.StopTimer()
	h.Reset()
}

// benchmarkCSHAKE is specialized to the Shake instances, which don't
// require a copy on reading output.
func benchmarkCSHAKE(b *testing.B, securityBits int, hfun func() *openssl.SHAKE, size, num int) {
	if !openssl.SupportsSHAKE(securityBits) {
		b.Skip("SHAKE not supported")
	}
	h := hfun()
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	d := make([]byte, 32)

	b.SetBytes(int64(size * num))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()
		for j := 0; j < num; j++ {
			h.Write(data)
		}
		h.Read(d)
	}
}

func BenchmarkCSHAKE128_MTU(b *testing.B)  { benchmarkCSHAKE(b, 128, openssl.NewSHAKE128, 1350, 1) }
func BenchmarkCSHAKE256_MTU(b *testing.B)  { benchmarkCSHAKE(b, 256, openssl.NewSHAKE256, 1350, 1) }
func BenchmarkCSHAKE256_16x(b *testing.B)  { benchmarkCSHAKE(b, 256, openssl.NewSHAKE256, 16, 1024) }
func BenchmarkCSHAKE256_1MiB(b *testing.B) { benchmarkCSHAKE(b, 256, openssl.NewSHAKE256, 1024, 1024) }

func BenchmarkCSHA3_512_1MiB(b *testing.B) {
	benchmarkHash(b, crypto.SHA3_512, openssl.NewSHA3_512, 1024, 1024)
}
