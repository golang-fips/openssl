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
	for i := 0; i < 5; i++ {
		// Run GC a few times to avoid false positives in leak detection.
		runtime.GC()
		// Sleep a bit to let the finalizers run.
		time.Sleep(10 * time.Millisecond)
	}
	openssl.CheckLeaks()
	os.Exit(status)
}
