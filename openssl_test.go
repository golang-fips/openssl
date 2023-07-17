//go:build linux

package openssl_test

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/golang-fips/openssl/v2"
)

// getVersion returns the OpenSSL version to use for testing.
func getVersion() string {
	v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	if v != "" {
		return v
	}
	// Try to find a supported version of OpenSSL on the system.
	// This is useful for local testing, where the user may not
	// have GO_OPENSSL_VERSION_OVERRIDE set.
	for _, v = range [...]string{"3", "1.1.1", "1.1", "11", "111", "1.0.2", "1.0.0", "10"} {
		if ok, _ := openssl.CheckVersion(v); ok {
			return v
		}
	}
	return ""
}

func TestMain(m *testing.M) {
	v := getVersion()
	fmt.Printf("Using libcrypto.so.%s\n", v)
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
	for i := 0; i < 5; i++ {
		// Run GC a few times to avoid false positives in leak detection.
		runtime.GC()
		// Sleep a bit to let the finalizers run.
		time.Sleep(10 * time.Millisecond)
	}
	openssl.CheckLeaks()
	os.Exit(status)
}

func TestCheckVersion(t *testing.T) {
	v := getVersion()
	exists, fips := openssl.CheckVersion(v)
	if !exists {
		t.Fatalf("OpenSSL version %q not found", v)
	}
	if want := openssl.FIPS(); want != fips {
		t.Fatalf("FIPS mismatch: want %v, got %v", want, fips)
	}
}
