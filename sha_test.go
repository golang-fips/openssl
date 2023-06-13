//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl_test

import (
	"bytes"
	"encoding"
	"hash"
	"io"
	"testing"

	"github.com/golang-fips/openssl"
)

func TestSha(t *testing.T) {
	msg := []byte("testig")
	var tests = []struct {
		name string
		fn   func() hash.Hash
	}{
		{"sha1", openssl.NewSHA1},
		{"sha224", openssl.NewSHA224},
		{"sha256", openssl.NewSHA256},
		{"sha384", openssl.NewSHA384},
		{"sha512", openssl.NewSHA512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := tt.fn()
			initSum := h.Sum(nil)
			n, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(msg) {
				t.Errorf("got: %d, want: %d", n, len(msg))
			}
			sum := h.Sum(nil)
			if size := h.Size(); len(sum) != size {
				t.Errorf("got: %d, want: %d", len(sum), size)
			}
			if bytes.Equal(sum, initSum) {
				t.Error("Write didn't change internal hash state")
			}

			state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Errorf("could not marshal: %v", err)
			}
			h2 := tt.fn()
			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Errorf("could not unmarshal: %v", err)
			}
			if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("0x%x != marshaled 0x%x", actual, actual2)
			}

			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}

			bw := h.(io.ByteWriter)
			for i := 0; i < len(msg); i++ {
				bw.WriteByte(msg[i])
			}
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}

			h.(io.StringWriter).WriteString(string(msg))
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestSHA_OneShot(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		name    string
		want    func() hash.Hash
		oneShot func([]byte) []byte
	}{
		{"sha1", openssl.NewSHA1, func(p []byte) []byte {
			b := openssl.SHA1(p)
			return b[:]
		}},
		{"sha224", openssl.NewSHA224, func(p []byte) []byte {
			b := openssl.SHA224(p)
			return b[:]
		}},
		{"sha256", openssl.NewSHA256, func(p []byte) []byte {
			b := openssl.SHA256(p)
			return b[:]
		}},
		{"sha384", openssl.NewSHA384, func(p []byte) []byte {
			b := openssl.SHA384(p)
			return b[:]
		}},
		{"sha512", openssl.NewSHA512, func(p []byte) []byte {
			b := openssl.SHA512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.oneShot(msg)
			h := tt.want()
			h.Write(msg)
			want := h.Sum(nil)
			if !bytes.Equal(got[:], want) {
				t.Errorf("got:%x want:%x", got, want)
			}
		})
	}
}

type cgoData struct {
	Data [16]byte
	Ptr  *cgoData
}

func TestCgo(t *testing.T) {
	// Test that Write does not cause cgo to scan the entire cgoData struct for pointers.
	// The scan (if any) should be limited to the [16]byte.
	defer func() {
		if err := recover(); err != nil {
			t.Error(err)
		}
	}()
	d := new(cgoData)
	d.Ptr = d
	h := openssl.NewSHA256()
	h.Write(d.Data[:])
	h.Sum(nil)

	openssl.SHA256(d.Data[:])
}

func BenchmarkHash8Bytes(b *testing.B) {
	b.StopTimer()
	h := openssl.NewSHA256()
	sum := make([]byte, h.Size())
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf)
		h.Sum(sum[:0])
	}
}

func BenchmarkSHA256(b *testing.B) {
	b.StopTimer()
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		openssl.SHA256(buf)
	}
}
