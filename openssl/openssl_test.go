//go:build linux && !android
// +build linux,!android

package openssl_test

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	err := Init()
	if err != nil {
		// An error here could mean that this Linux distro does not have a supported OpenSSL version
		// or that there is a bug in the Init code.
		panic(err)
	}
	fmt.Println("OpenSSL version:", VersionText())
	os.Exit(m.Run())
}
