//go:build go1.26

package openssl_test

import (
	"crypto/fips140"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

func TestHMACNonApprovedKey(t *testing.T) {
	// Test that HMAC with non-approved key length can be used without
	// enforcement

	h := openssl.NewHMAC(openssl.NewSHA256, []byte("short key"))
	if h != nil {
		t.Skip("short key is allowed")
	}

	// Note not all FIPS modules might support "key-check:0" param
	// Thus this test case may still fail
	fips140.WithoutEnforcement(func() {
		h = openssl.NewHMAC(openssl.NewSHA256, []byte("short key"))
	})

	if h == nil {
		t.Fatalf("HMAC with key-check:0 and short key failed to init")
	}
}
