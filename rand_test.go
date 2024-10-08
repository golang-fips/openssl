package openssl_test

import (
	"go/version"
	"runtime"
	"strings"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

func TestRand(t *testing.T) {
	_, err := openssl.RandReader.Read(make([]byte, 5))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAllocations(t *testing.T) {
	n := int(testing.AllocsPerRun(10, func() {
		buf := make([]byte, 32)
		openssl.RandReader.Read(buf)
		sink ^= buf[0]
	}))
	want := 1
	ver := strings.TrimPrefix(runtime.Version(), "devel ")
	if version.Compare(ver, "go1.24") >= 0 {
		want = 0
	}
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}
