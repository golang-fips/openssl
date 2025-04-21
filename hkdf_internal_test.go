package openssl

import (
	"encoding/binary"
	"bytes"
	"testing"
)


func makeInfo(fullLabel string, context []byte) []byte {
	totalLen := 1 + len(fullLabel) + 1 + len(context)

	info := make([]byte, 2+totalLen)
	binary.BigEndian.PutUint16(info[0:2], uint16(totalLen))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = byte(len(context))
	copy(info[4+len(fullLabel):], context)

	return info
}

func TestParseForTLS13_Valid(t *testing.T) {
	tests := []struct {
		name         string
		labelPrefix  string
		label        string
		context      []byte
	}{
		{"IV", "tls13 ", "iv", []byte{}},
		{"Traffic Secret", "tls13 ", "c hs traffic", []byte{0xaa, 0xbb}},
		{"Finished", "tls13 ", "finished", []byte{0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := makeInfo(tt.labelPrefix + tt.label, tt.context)
			label, context, isTLS13 := parseForTLS13(info)
			if !isTLS13 {
				t.Errorf("Expected TLS13 label, got isTLS13=false")
			}
			if !bytes.Equal(label, []byte(tt.label)) {
				t.Errorf("Label mismatch: got %q, want %q", label, tt.label)
			}
			if !bytes.Equal(context, tt.context) {
				t.Errorf("Context mismatch: got %x, want %x", context, tt.context)
			}
		})
	}
}

func TestParseForTLS13_Invalid(t *testing.T) {
	tests := []struct {
		name string
		info []byte
	}{
		{"Missing tls13 prefix", makeInfo("foobar", []byte{0x01})},
		{"Too short", []byte{0x00}},
		{"Label length exceeds buffer", []byte{0xFF, 't'}},
		{"Incomplete prefix", []byte{0x06, 't', 'l', 's', '1', '3', ' ', 0x00 }}, // discovered by the fuzzer
		{"Correct prefix but missing context", []byte{0x08, 't', 'l', 's', '1', '3', ' ', 'i', 'v'}},
		{"Correct prefix but truncated context", []byte{0x08, 't', 'l', 's', '1', '3', ' ', 'i', 'v', 0x02}},
		{"Correct prefix but truncated context", []byte{0x06, 't', 'l', 's', '1', '3', ' ', 'i', 'v', 0x02}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, context, isTLS13 := parseForTLS13(tt.info)
			if isTLS13 {
				t.Errorf("Expected isTLS13=false, got true")
			}
			if label != nil {
				t.Errorf("Expected label=nil, got %q", label)
			}
			if context != nil {
				t.Errorf("Expected context=nil, got %x", context)
			}
		})
	}
}

// run the fuzzer with:
// go test -fuzz=FuzzParseForTLS13
func FuzzParseForTLS13(f *testing.F) {
	// Seed with known-good examples
	f.Add([]byte{0x08, 't', 'l', 's', '1', '3', ' ', 'i', 'v', 0x00}) // "tls13 iv" + empty context
	f.Add([]byte{0x0c, 't', 'l', 's', '1', '3', ' ', 'c', ' ', 'h', 's', ' ', 't', 'r', 'a', 'f', 'f', 'i', 'c', 0x02, 0xAA, 0xBB})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic with input: %x — %v", data, r)
			}
		}()

		label, context, isTLS13 := parseForTLS13(data)

		if isTLS13 {
			if len(label) == 0 {
				t.Errorf("isTLS13=true but label is empty (input: %x)", data)
			}
			// Context can be 0-length, but shouldn't go out of bounds
			if context == nil {
				t.Errorf("isTLS13=true but context is nil (input: %x)", data)
			}
		}
	})
}
