//go:build linux && !android
// +build linux,!android

package openssl_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/golang-fips/openssl/openssl"
)

func TestMain(m *testing.M) {
	exitVal := m.Run()
	runtime.GC()
	openssl.CheckLeaks()
	os.Exit(exitVal)
}
