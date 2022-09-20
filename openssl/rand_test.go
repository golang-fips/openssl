//go:build linux && !android
// +build linux,!android

package openssl

import (
	"testing"
)

func TestRand(t *testing.T) {
	_, err := RandReader.Read(make([]byte, 5))
	if err != nil {
		t.Fatal(err)
	}
}
