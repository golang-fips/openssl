package openssl_test

import (
	"bytes"
	"crypto"
	"encoding"
	"hash"
	"io"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

func cryptoToHash(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.MD4:
		return openssl.NewMD4
	case crypto.MD5:
		return openssl.NewMD5
	case crypto.SHA1:
		return openssl.NewSHA1
	case crypto.SHA224:
		return openssl.NewSHA224
	case crypto.SHA256:
		return openssl.NewSHA256
	case crypto.SHA384:
		return openssl.NewSHA384
	case crypto.SHA512:
		return openssl.NewSHA512
	case crypto.SHA3_224:
		return openssl.NewSHA3_224
	case crypto.SHA3_256:
		return openssl.NewSHA3_256
	case crypto.SHA3_384:
		return openssl.NewSHA3_384
	case crypto.SHA3_512:
		return openssl.NewSHA3_512
	}
	return nil
}

func TestHash(t *testing.T) {
	msg := []byte("testing")
	var tests = []crypto.Hash{
		crypto.MD4,
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_384,
		crypto.SHA3_512,
	}
	for _, ch := range tests {
		ch := ch
		t.Run(ch.String(), func(t *testing.T) {
			t.Parallel()
			if !openssl.SupportsHash(ch) {
				t.Skip("skipping: not supported")
			}
			h := cryptoToHash(ch)()
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
			if _, ok := h.(encoding.BinaryMarshaler); ok {
				state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
				if err != nil {
					t.Errorf("could not marshal: %v", err)
				}
				h2 := cryptoToHash(ch)()
				if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
					t.Errorf("could not unmarshal: %v", err)
				}
				if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
					t.Errorf("0x%x != marshaled 0x%x", actual, actual2)
				}
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

func TestHash_OneShot(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		h       crypto.Hash
		oneShot func([]byte) []byte
	}{
		{crypto.SHA1, func(p []byte) []byte {
			b := openssl.SHA1(p)
			return b[:]
		}},
		{crypto.SHA224, func(p []byte) []byte {
			b := openssl.SHA224(p)
			return b[:]
		}},
		{crypto.SHA256, func(p []byte) []byte {
			b := openssl.SHA256(p)
			return b[:]
		}},
		{crypto.SHA384, func(p []byte) []byte {
			b := openssl.SHA384(p)
			return b[:]
		}},
		{crypto.SHA512, func(p []byte) []byte {
			b := openssl.SHA512(p)
			return b[:]
		}},
		{crypto.SHA3_224, func(p []byte) []byte {
			b := openssl.SHA3_224(p)
			return b[:]
		}},
		{crypto.SHA3_256, func(p []byte) []byte {
			b := openssl.SHA3_256(p)
			return b[:]
		}},
		{crypto.SHA3_384, func(p []byte) []byte {
			b := openssl.SHA3_384(p)
			return b[:]
		}},
		{crypto.SHA3_512, func(p []byte) []byte {
			b := openssl.SHA3_512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.h.String(), func(t *testing.T) {
			if !openssl.SupportsHash(tt.h) {
				t.Skip("skipping: not supported")
			}
			got := tt.oneShot(msg)
			h := cryptoToHash(tt.h)()
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
