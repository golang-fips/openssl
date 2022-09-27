//go:build linux && !android
// +build linux,!android

package openssl_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/golang-fips/openssl-fips/openssl"
)

func TestMain(m *testing.M) {
	err := openssl.Init("")
	if err != nil {
		// An error here could mean that this Linux distro does not have a supported OpenSSL version
		// or that there is a bug in the Init code.
		panic(err)
	}
	_ = openssl.SetFIPS(true) // Skip the error as we still want to run the tests on machines without FIPS support.
	fmt.Println("OpenSSL version:", openssl.VersionText())
	fmt.Println("FIPS enabled:", openssl.FIPS())
	os.Exit(m.Run())
}
