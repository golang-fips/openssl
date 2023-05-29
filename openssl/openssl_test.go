//go:build linux && !android
// +build linux,!android

package openssl_test

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/golang-fips/openssl-fips/openssl"
)

func TestMain(m *testing.M) {
	v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	err := openssl.Init(v)
	if err != nil {
		// An error here could mean that this Linux distro does not have a supported OpenSSL version
		// or that there is a bug in the Init code.
		panic(err)
	}
	_ = openssl.SetFIPS(true) // Skip the error as we still want to run the tests on machines without FIPS support.
	fmt.Println("OpenSSL version:", openssl.VersionText())
	fmt.Println("FIPS enabled:", openssl.FIPS())
	status := m.Run()
	runtime.GC()
	openssl.CheckLeaks()
	os.Exit(status)
}

func TestCheckVersion(t *testing.T) {
	v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	exists, fips := openssl.CheckVersion(v)
	if !exists {
		t.Fatalf("OpenSSL version %q not found", v)
	}
	if want := openssl.FIPS(); want != fips {
		t.Fatalf("FIPS mismatch: want %v, got %v", want, fips)
	}
}
