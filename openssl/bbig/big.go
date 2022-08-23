// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a mirror of crypto/internal/boring/bbig/big.go.

package bbig

import (
	"math/big"
	"unsafe"

	"github.com/golang-fips/openssl-fips/openssl"
)

func Enc(b *big.Int) openssl.BigInt {
	if b == nil {
		return nil
	}
	x := b.Bits()
	if len(x) == 0 {
		return openssl.BigInt{}
	}
	// TODO: Use unsafe.Slice((*uint)(&x[0]), len(x)) once go1.16 is no longer supported.
	return (*(*[]uint)(unsafe.Pointer(&x)))[:len(x)]
}

func Dec(b openssl.BigInt) *big.Int {
	if b == nil {
		return nil
	}
	if len(b) == 0 {
		return new(big.Int)
	}
	// TODO: Use unsafe.Slice((*uint)(&b[0]), len(b)) once go1.16 is no longer supported.
	x := (*(*[]big.Word)(unsafe.Pointer(&b)))[:len(b)]
	return new(big.Int).SetBits(x)
}
