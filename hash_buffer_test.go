package openssl_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

// TestHashBuffering tests the internal buffering mechanism
func TestHashBuffering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		writes [][]byte
	}{
		{
			name:   "small-writes",
			writes: [][]byte{[]byte("hello"), []byte(" "), []byte("world")},
		},
		{
			name:   "single-byte-writes",
			writes: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
		},
		{
			name: "buffer-boundary",
			// Write exactly 64 bytes (buffer size) in small chunks
			writes: [][]byte{
				bytes.Repeat([]byte("a"), 10),
				bytes.Repeat([]byte("b"), 10),
				bytes.Repeat([]byte("c"), 10),
				bytes.Repeat([]byte("d"), 10),
				bytes.Repeat([]byte("e"), 10),
				bytes.Repeat([]byte("f"), 10),
				bytes.Repeat([]byte("g"), 4),
			},
		},
		{
			name: "exceed-buffer",
			// Write more than 64 bytes
			writes: [][]byte{
				bytes.Repeat([]byte("a"), 50),
				bytes.Repeat([]byte("b"), 50),
			},
		},
		{
			name: "large-single-write",
			// Write more than buffer size in one go
			writes: [][]byte{bytes.Repeat([]byte("x"), 128)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := openssl.NewSHA256()
			// Test that empty hash is correct
			emptySum := h.Sum(nil)
			wantEmpty := sha256.Sum256(nil)
			if !bytes.Equal(emptySum, wantEmpty[:]) {
				t.Errorf("empty hash = %s, want %s", emptySum, wantEmpty)
			}

			// Write data in chunks
			var all []byte
			for _, write := range tt.writes {
				n, err := h.Write(write)
				if err != nil {
					t.Fatalf("Write failed: %v", err)
				}
				if n != len(write) {
					t.Fatalf("Write returned %d, want %d", n, len(write))
				}
				all = append(all, write...)
			}

			// Get the hash
			sum1 := h.Sum(nil)

			// Reset and hash all at once to verify correctness
			h.Reset()
			h.Write(all)
			sum2 := h.Sum(nil)

			if !bytes.Equal(sum1, sum2) {
				t.Errorf("buffered hash = %x, want %x", sum1, sum2)
			}

			// Verify Reset works and returns to empty state
			h.Reset()
			sumAfterReset := h.Sum(nil)
			if !bytes.Equal(sumAfterReset, emptySum) {
				t.Errorf("hash after Reset = %x, want %x", sumAfterReset, emptySum)
			}
		})
	}
}

// TestHashBufferingWithClone tests that Clone properly copies buffered data
func TestHashBufferingWithClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		data  []byte
		extra []byte
	}{
		{
			name:  "SHA256-buffered-clone",
			data:  []byte("hello"), // Small enough to stay in buffer
			extra: []byte(" world"),
		},
		{
			name:  "SHA256-single-byte-clone",
			data:  []byte("a"),
			extra: []byte("b"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write some data that stays in buffer
			h := openssl.NewSHA256().(openssl.HashCloner)
			h.Write(tt.data)

			// Clone while data is buffered
			h2, err := h.Clone()
			if err != nil {
				t.Fatalf("Clone failed: %v", err)
			}

			// Both should produce same hash
			sum1 := h.Sum(nil)
			sum2 := h2.Sum(nil)
			if !bytes.Equal(sum1, sum2) {
				t.Errorf("clone hash mismatch: got %x, want %x", sum2, sum1)
			}

			// Write more to original
			h.Write(tt.extra)
			sum3 := h.Sum(nil)

			// Clone should be unaffected
			sum4 := h2.Sum(nil)
			if !bytes.Equal(sum2, sum4) {
				t.Errorf("clone was affected by original: got %x, want %x", sum4, sum2)
			}

			// And they should be different
			if bytes.Equal(sum3, sum4) {
				t.Error("original and clone have same hash after diverging")
			}
		})
	}
}

// TestHashBufferingMultipleSum tests that Sum can be called multiple times
func TestHashBufferingMultipleSum(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()

	// Write some data (stays in buffer)
	data := []byte("test data")
	h.Write(data)

	// Call Sum multiple times - should return same result
	sum1 := h.Sum(nil)
	sum2 := h.Sum(nil)
	sum3 := h.Sum(nil)

	if !bytes.Equal(sum1, sum2) || !bytes.Equal(sum2, sum3) {
		t.Errorf("multiple Sum calls returned different results: %x, %x, %x", sum1, sum2, sum3)
	}

	// Should still be able to write more
	h.Write([]byte(" more"))
	sum4 := h.Sum(nil)

	// This should be different
	if bytes.Equal(sum1, sum4) {
		t.Error("hash didn't change after additional write")
	}
}

// TestHashBufferingFastPath tests the fast path optimization when ctx is nil
func TestHashBufferingFastPath(t *testing.T) {
	t.Parallel()
	// Test that small data that fits in buffer uses fast path
	h := openssl.NewSHA256()

	// Write small amount of data that fits in buffer (< 64 bytes)
	data := []byte("small data")
	h.Write(data)

	// Sum should use fast path (EVP_Digest) since ctx is still nil
	sum1 := h.Sum(nil)

	// Verify by comparing with one-shot hash
	sum2 := openssl.SHA256(data)

	if !bytes.Equal(sum1[:], sum2[:]) {
		t.Errorf("fast path hash = %x, want %x", sum1, sum2)
	}
}

// TestHashBufferingEmptyWrites tests edge cases with empty writes
func TestHashBufferingEmptyWrites(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()

	// Empty write should do nothing
	n, err := h.Write([]byte{})
	if err != nil || n != 0 {
		t.Errorf("empty Write returned (%v, %d), want (nil, 0)", err, n)
	}

	// Hash should still be empty hash
	emptyHash := openssl.SHA256([]byte{})
	sum := h.Sum(nil)
	if !bytes.Equal(sum, emptyHash[:]) {
		t.Errorf("hash after empty write = %x, want %x", sum, emptyHash)
	}

	// Multiple empty writes
	h.Write([]byte{})
	h.Write([]byte{})
	h.Write([]byte{})

	sum2 := h.Sum(nil)
	if !bytes.Equal(sum2, emptyHash[:]) {
		t.Errorf("hash after multiple empty writes = %x, want %x", sum2, emptyHash)
	}
}

// TestHashBufferingWithAppend tests Sum with non-nil input slice
func TestHashBufferingWithAppend(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()
	data := []byte("test")
	h.Write(data)

	// Sum with prefix
	prefix := []byte("prefix:")
	result := h.Sum(prefix)

	// Should have prefix followed by hash
	if !bytes.HasPrefix(result, prefix) {
		t.Errorf("result doesn't have prefix: %x", result)
	}

	// Extract hash part
	hash := result[len(prefix):]

	// Verify hash is correct
	expectedHash := openssl.SHA256(data)
	if !bytes.Equal(hash, expectedHash[:]) {
		t.Errorf("appended hash = %x, want %x", hash, expectedHash)
	}
}

// TestHashBufferingWriteByte tests WriteByte with buffering
func TestHashBufferingWriteByte(t *testing.T) {
	t.Parallel()
	// WriteByte is available on the concrete types
	h := openssl.NewSHA256()

	// Write bytes one at a time
	data := []byte("hello")
	for _, b := range data {
		if err := h.(io.ByteWriter).WriteByte(b); err != nil {
			t.Fatalf("WriteByte failed: %v", err)
		}
	}

	sum1 := h.Sum(nil)

	// Compare with bulk write
	h2 := openssl.NewSHA256()
	h2.Write(data)
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("WriteByte hash = %x, want %x", sum1, sum2)
	}
}

// TestHashBufferingWriteString tests WriteString with buffering
func TestHashBufferingWriteString(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()

	// Write string
	const s = "hello world"

	n, err := h.(io.StringWriter).WriteString(s)
	if err != nil || n != len(s) {
		t.Fatalf("WriteString returned (%v, %d), want (nil, %d)", err, n, len(s))
	}

	sum1 := h.Sum(nil)

	// Compare with Write
	h2 := openssl.NewSHA256()
	h2.Write([]byte(s))
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("WriteString hash = %x, want %x", sum1, sum2)
	}
}

// TestHashBufferingResetWithBufferedData tests Reset with data in buffer
func TestHashBufferingResetWithBufferedData(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()

	// Write data that stays in buffer
	h.Write([]byte("some data"))

	// Reset should clear buffer
	h.Reset()

	// Should now be empty hash
	emptyHash := openssl.SHA256([]byte{})
	sum := h.Sum(nil)

	if !bytes.Equal(sum, emptyHash[:]) {
		t.Errorf("hash after Reset = %x, want %x", sum, emptyHash)
	}
}

// TestHashBufferingLargeData tests buffering with data larger than buffer
func TestHashBufferingLargeData(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()

	// Create data larger than buffer (64 bytes)
	largeData := bytes.Repeat([]byte("x"), 1000)

	// Write in chunks that will cause multiple buffer flushes
	chunkSize := 10
	for i := 0; i < len(largeData); i += chunkSize {
		end := i + chunkSize
		if end > len(largeData) {
			end = len(largeData)
		}
		h.Write(largeData[i:end])
	}

	sum1 := h.Sum(nil)

	// Compare with one-shot hash
	sum2 := openssl.SHA256(largeData)

	if !bytes.Equal(sum1, sum2[:]) {
		t.Errorf("chunked hash = %x, want %x", sum1, sum2)
	}
}

// TestHashBufferingMixedSizes tests various write sizes
func TestHashBufferingMixedSizes(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()

	var all []byte

	// Mix of small and large writes
	writes := [][]byte{
		[]byte("a"),                    // 1 byte
		bytes.Repeat([]byte("b"), 10),  // 10 bytes
		[]byte("c"),                    // 1 byte
		bytes.Repeat([]byte("d"), 100), // 100 bytes (exceeds buffer)
		[]byte("e"),                    // 1 byte
		bytes.Repeat([]byte("f"), 5),   // 5 bytes
		bytes.Repeat([]byte("g"), 200), // 200 bytes (exceeds buffer)
		[]byte("h"),                    // 1 byte
	}

	for _, w := range writes {
		h.Write(w)
		all = append(all, w...)
	}

	sum1 := h.Sum(nil)
	sum2 := openssl.SHA256(all)

	if !bytes.Equal(sum1, sum2[:]) {
		t.Errorf("mixed sizes hash = %x, want %x", sum1, sum2)
	}
}

// TestHashBufferingCloneAtBufferBoundary tests cloning when buffer is exactly full
func TestHashBufferingCloneAtBufferBoundary(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256().(openssl.HashCloner)

	// Write exactly 64 bytes (buffer size)
	data := bytes.Repeat([]byte("a"), 64)
	h.Write(data)

	// Clone at buffer boundary
	h2, err := h.Clone()
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}

	sum1 := h.Sum(nil)
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("clone at boundary: got %x, want %x", sum2, sum1)
	}
}
