//go:build linux && !android
// +build linux,!android

package openssl_test

import (
	"testing"

	"github.com/golang-fips/openssl"
)

func TestRand(t *testing.T) {
	_, err := openssl.RandReader.Read(make([]byte, 5))
	if err != nil {
		t.Fatal(err)
	}
}
