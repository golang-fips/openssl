package openssl_test

import (
	"cmp"
	"fmt"
	"go/version"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/golang-fips/openssl/v2"
	"github.com/golang-fips/openssl/v2/internal/ossl"
	"github.com/golang-fips/openssl/v2/osslsetup"
)

// sink is used to prevent the compiler from optimizing out the allocations.
var sink uint8

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
	versions := []string{"3", "1.1.1", "1.1", "11", "111"}
	if runtime.GOOS == "windows" {
		if runtime.GOARCH == "amd64" {
			versions = []string{"libcrypto-3-x64", "libcrypto-3", "libcrypto-1_1-x64", "libcrypto-1_1", "libeay64", "libeay32"}
		} else {
			versions = []string{"libcrypto-3", "libcrypto-1_1", "libeay32"}
		}
	}
	for _, v := range versions {
		switch runtime.GOOS {
		case "windows":
			v += ".dll"
		case "darwin":
			v = "libcrypto." + v + ".dylib"
		default:
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
	_ = osslsetup.SetFIPS(true) // Skip the error as we still want to run the tests on machines without FIPS support.
	fmt.Println("OpenSSL version:", osslsetup.VersionText())
	fmt.Println("FIPS enabled:", osslsetup.FIPS())
	fmt.Println("FIPS capable:", osslsetup.FIPSCapable())
	status := m.Run()
	for range 5 {
		// Run GC a few times to avoid false positives in leak detection.
		runtime.GC()
		// Sleep a bit to let the finalizers run.
		time.Sleep(10 * time.Millisecond)
	}
	if !testErrorStack() {
		status = cmp.Or(status, 1)
	}
	os.Exit(status)
}

// testErrorStack checks that the OpenSSL error queue is empty
// on all threads. It returns true if the error queue is empty.
// If not, it prints the error stacks and returns false.
func testErrorStack() bool {
	var wg sync.WaitGroup
	var stack string
	var mu sync.Mutex
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Lock the OS thread to increase the chance of each
			// goroutine running on a different thread.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if ossl.ERR_peek_error() != 0 {
				mu.Lock()
				defer mu.Unlock()
				stack += errorStack()
			}
		}()
	}
	wg.Wait()
	if stack != "" {
		fmt.Printf("OpenSSL error queue not empty at exit:\n%s", stack)
	}
	return stack == ""
}

func errorStack() string {
	// BIO operations using BIO_s_mem should not fail.
	bio, err := ossl.BIO_new(ossl.BIO_s_mem())
	if err != nil {
		panic(err)
	}
	defer ossl.BIO_free(bio)
	ossl.ERR_print_errors(bio)
	var data *byte
	n := ossl.BIO_ctrl(bio, ossl.BIO_CTRL_INFO, 0, unsafe.Pointer(&data))
	buf := make([]byte, n)
	copy(buf, unsafe.Slice(data, n))
	return string(buf)
}

func TestCheckVersion(t *testing.T) {
	v := getVersion()
	exists, fips := osslsetup.CheckVersion(v)
	if !exists {
		t.Fatalf("OpenSSL version %q not found", v)
	}
	if want := osslsetup.FIPS(); want != fips {
		t.Fatalf("FIPS mismatch: want %v, got %v", want, fips)
	}
}

// compareCurrentVersion compares v with [runtime.Version].
// See [go/versions.Compare] for information about
// v format and comparison rules.
func compareCurrentVersion(v string) int {
	ver := strings.TrimPrefix(runtime.Version(), "devel ")
	return version.Compare(ver, v)
}

func TestSetFIPS(t *testing.T) {
	fipsEnabled := osslsetup.FIPS()
	t.Cleanup(func() {
		// Restore the previous FIPS mode.
		err := osslsetup.SetFIPS(fipsEnabled)
		if err != nil {
			t.Fatal(err)
		}
	})

	if err := osslsetup.SetFIPS(fipsEnabled); err != nil {
		// Test that we can set FIPS mode to the current state
		// without error.
		t.Fatalf("SetFIPS(%v) failed: %v", fipsEnabled, err)
	}
	if got := osslsetup.FIPS(); got != fipsEnabled {
		// Test that the FIPS mode hasn't been changed by the
		// previous SetFIPS call.
		t.Fatalf("FIPS mode mismatch: want %v, got %v", fipsEnabled, got)
	}

	if fipsEnabled &&
		defaultProviderAvailable() {
		// Test that we can disable FIPS mode if it was enabled
		// when the built-in provider is available.
		err := osslsetup.SetFIPS(false)
		if err != nil {
			t.Fatalf("SetFIPS(false) failed: %v", err)
		}
	} else if !fipsEnabled &&
		(symCryptProviderAvailable() || fipsProviderAvailable()) {
		// Test that we can enable FIPS mode if it was disabled
		// when the provider is known to support FIPS mode.
		err := osslsetup.SetFIPS(true)
		if err != nil {
			t.Fatalf("SetFIPS(true) failed: %v", err)
		}
	} else {
		t.Skip("FIPS mode is not supported")
	}
}

func TestFIPSCapable(t *testing.T) {
	got := osslsetup.FIPSCapable()
	want := osslsetup.FIPS()
	if !want && symCryptProviderAvailable() {
		// The SymCrypt provider is FIPS-capable.
		want = true
	}
	if got != want {
		t.Fatalf("FIPSCapable mismatch: want %v, got %v", want, got)
	}
}

func TestErrorMultithread(t *testing.T) {
	// Test that we get the expected error when generating a key
	// with an invalid size in a multithreaded environment
	// while running other OpenSSL operations.
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _, _, _, _, _, _, _, err := openssl.GenerateKeyRSA(1)
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			str := err.Error()
			if !strings.Contains(str, "key size too small") {
				t.Errorf("expected error to contain 'rsa routines', got %q", err)
			}
			if strings.Contains(str, "\x00") {
				t.Errorf("expected error to not contain null byte, got %q", str)
			}
		}()
		go func() {
			defer wg.Done()
			// This should never fail.
			openssl.SHA256([]byte("test"))
		}()
	}
	wg.Wait()
}

func TestErrorAllocs(t *testing.T) {
	n := testing.AllocsPerRun(10, func() {
		openssl.GenerateKeyRSA(1)
	})
	max := 4
	if int(n) > max {
		t.Fatalf("Expected less than max allocations, got %d", int(n))
	}
}

func BenchmarkError(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		openssl.GenerateKeyRSA(1)
	}
}

var symCryptProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("symcryptprovider")
})

var fipsProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("fips")
})

var defaultProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("default")
})

// isProviderAvailable checks if the provider with the given name is available.
// This helper is used within openssl_test.go to check provider availability for tests,
// and must be defined here as test files can't access C functions directly.
func isProviderAvailable(name string) bool {
	if osslsetup.VersionMajor() == 1 {
		return false
	}
	return ossl.OSSL_PROVIDER_available(nil, unsafe.StringData(name+"\x00")) == 1
}
