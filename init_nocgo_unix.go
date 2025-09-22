//go:build unix && !cmd_go_bootstrap && !cgo

package openssl

import (
	"errors"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

func dlopen(file string) (handle unsafe.Pointer, err error) {
	handle = ossl.Dlopen(unsafe.StringData(file+"\x00"), 1|4)
	if handle == nil {
		return nil, errors.New(goString(ossl.Dlerror()))
	}
	return handle, nil
}

func dlclose(handle unsafe.Pointer) error {
	if ossl.Dlclose(handle) != 0 {
		errstr := goString(ossl.Dlerror())
		return errors.New("openssl: can't close libcrypto: " + errstr)
	}
	return nil
}
