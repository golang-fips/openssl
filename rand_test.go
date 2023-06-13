//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

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
