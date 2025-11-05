package openssl_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

// TestHashBufferingWithClone tests that Clone properly copies buffered data
func TestHashBufferingWithClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		data  []byte
		extra []byte
	}{
		{
			name:  "buffered-clone",
			data:  []byte("hello"), // Small enough to stay in buffer
			extra: []byte(" world"),
		},
		{
			name:  "single-byte-clone",
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

	// Write small amount of data that fits in buffer
	data := bytes.Repeat([]byte("a"), openssl.HashBufSize-56)
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

// TestHashBufferingExactFill tests when a single write fills the buffer exactly
func TestHashBufferingExactFill(t *testing.T) {
	t.Parallel()
	h := openssl.NewSHA256()

	// First, write some data that leaves room in buffer
	// Buffer is openssl.HashBufSize bytes, so write most of it first
	firstWrite := bytes.Repeat([]byte("a"), openssl.HashBufSize-56)
	h.Write(firstWrite)

	// Now write exactly 56 bytes to fill buffer to openssl.HashBufSize
	secondWrite := bytes.Repeat([]byte("b"), 56)
	h.Write(secondWrite)

	// Get hash
	sum1 := h.Sum(nil)

	// Compare with expected
	allData := append(firstWrite, secondWrite...)
	expected := openssl.SHA256(allData)

	if !bytes.Equal(sum1, expected[:]) {
		t.Errorf("exact fill hash = %x, want %x", sum1, expected)
	}

	// Also test writing exactly buffer size in one go
	h2 := openssl.NewSHA256()
	exactBufSize := bytes.Repeat([]byte("x"), openssl.HashBufSize)
	h2.Write(exactBufSize)

	sum2 := h2.Sum(nil)
	expected2 := openssl.SHA256(exactBufSize)

	if !bytes.Equal(sum2, expected2[:]) {
		t.Errorf("exact buffer size write hash = %x, want %x", sum2, expected2)
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

	// Create data larger than buffer
	largeData := bytes.Repeat([]byte("x"), openssl.HashBufSize*4)

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

	// Write exactly openssl.HashBufSize bytes
	data := bytes.Repeat([]byte("a"), openssl.HashBufSize)
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
