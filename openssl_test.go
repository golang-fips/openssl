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
		if runtime.GOOS == "linux" {
			return "libcrypto.so." + v
		}
		return v
	}
	// Try to find a supported version of OpenSSL on the system.
	// This is useful for local testing, where the user may not
	// have GO_OPENSSL_VERSION_OVERRIDE set.
	versions := []string{"3", "1.1.1", "1.1", "11", "111", "1.0.2", "1.0.0", "10"}
	if runtime.GOOS == "windows" {
		if runtime.GOARCH == "amd64" {
			versions = []string{"libcrypto-3-x64", "libcrypto-3", "libcrypto-1_1-x64", "libcrypto-1_1", "libeay64", "libeay32"}
		} else {
			versions = []string{"libcrypto-3", "libcrypto-1_1", "libeay32"}
		}
	}
	for _, v = range versions {
		if runtime.GOOS == "windows" {
			v += ".dll"
		} else if runtime.GOOS == "darwin" {
			v = "libcrypto." + v + ".dylib"
		} else {
			v = "libcrypto.so." + v
		}
		if ok, _ := openssl.CheckVersion(v); ok {
			return v
		}
	}
	return "libcrypto.so"
}

func TestMain(m *testing.M) {
	v := getVersion()
	fmt.Printf("Using %s\n", v)
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
	for range 5 {
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

func TestProvider(t *testing.T) {
	if openssl.MajorVersion == 1 {
		t.Skip("Provider is not supported in OpenSSL 1")
	}
	tests := []struct {
		name string
		fn   func() any
	}{
		{"sha256", func() any { return openssl.NewSHA256() }},
		{"rsaPub", func() any {
			_, pub := newRSAKey(t, 1024)
			return pub
		}},
		{"rsaPriv", func() any {
			priv, _ := newRSAKey(t, 1024)
			return priv
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			md := openssl.NewSHA256()
			name, _, _ := openssl.Provider(md)
			if name == "" {
				t.Fatal("Provider: empty name")
			}
		})
	}
}
