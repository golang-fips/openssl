//go:build !cmd_go_bootstrap

package openssl_test

import (
	"fmt"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

func TestScrypt(t *testing.T) {
	hash, err := openssl.Scrypt("testpass01", []byte("abc123"), 1<<14, 8, 1, 32<<20, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) == 0 {
		t.Error("zero length hash")
	}
	hexhash := fmt.Sprintf("%x", hash)
	exp := "e6a3569950bf90e88d2f114c3d43f2d103cf3c13cf1579095e88ff5b3b3eb379cad31d26aa533e0f32c10666bbcc9c1cac2775a8a60d55d55d63c401927e905e"
	if hexhash != exp {
		t.Errorf("expected %q, got %q", exp, hexhash)
	}
}

func TestScrypt_Err(t *testing.T) {
	_, err := openssl.Scrypt("testpass01", []byte("abc123"), 1<<14, 0, 0, 32<<20, 64)
	if err == nil {
		t.Error("expected an error when using zeros for r and p")
	}
	_, err = openssl.Scrypt("x", []byte("y"), 1<<14, 8, 1, 1<<20, 32)
	if err == nil {
		t.Error("expected memory limit error")
	}
}
