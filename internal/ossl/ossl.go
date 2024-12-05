//go:build cgo

package ossl

import (
	"errors"
	"strconv"
	"strings"
	"unsafe"
)

//go:generate go run github.com/golang-fips/openssl/v2/internal/mkcgo -out zossl.go --package ossl --lib crypto --include ossl.h api.h

var vMajor, vMinor, vPatch int

func LoadLcrypto(handle unsafe.Pointer) {
	mkcgoLoad_crypto(handle)
	vMajor = Go_openssl_version_major(handle)
	vMinor = Go_openssl_version_minor(handle)
	vPatch = Go_openssl_version_minor(handle)
}

func newError(msg string) error {
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):")
	for {
		var (
			e    uint64
			file *byte
			line int32
		)
		if vMajor == 1 {
			e = ERR_get_error_line(&file, &line)
		} else {
			e = ERR_get_error_all(&file, &line, nil, nil, nil)
		}
		if e == 0 {
			break
		}
		b.WriteByte('\n')
		var buf [256]byte
		ERR_error_string_n(e, &buf[0], len(buf))
		b.WriteString(string(buf[:]) + "\n\t" + goString(file) + ":" + strconv.Itoa(int(line)))
	}
	return errors.New(b.String())
}

// goString converts a C null-terminated string to a Go string.
func goString(p *byte) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	n := 0
	for *(*byte)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}
	return string(unsafe.Slice(p, n))
}

func OpenSSL_version(typ int32) *byte {
	if vMajor == 1 && vMinor == 0 {
		return _SSLeay_version(typ)
	}
	return _OpenSSL_version(typ)
}

func EVP_MD_CTX_free(ctx EVP_MD_CTX_PTR) {
	if vMajor == 1 && vMinor == 0 {
		_EVP_MD_CTX_destroy(ctx)
	} else {
		_EVP_MD_CTX_free(ctx)
	}
}

func EVP_MD_CTX_new() (EVP_MD_CTX_PTR, error) {
	if vMajor == 1 && vMinor == 0 {
		return _EVP_MD_CTX_create()
	}
	return _EVP_MD_CTX_new()
}

func EVP_MD_get_size(md EVP_MD_PTR) int32 {
	if vMajor == 1 {
		return _EVP_MD_size(md)
	}
	return _EVP_MD_get_size(md)
}

func EVP_MD_get_block_size(md EVP_MD_PTR) int32 {
	if vMajor == 1 {
		return _EVP_MD_block_size(md)
	}
	return _EVP_MD_get_block_size(md)
}

func EVP_PKEY_get_size(pkey EVP_PKEY_PTR) int32 {
	if vMajor == 1 {
		return _EVP_PKEY_size(pkey)
	}
	return _EVP_PKEY_get_size(pkey)
}

func EVP_PKEY_get_bits(pkey EVP_PKEY_PTR) int32 {
	if vMajor == 1 {
		return _EVP_PKEY_bits(pkey)
	}
	return _EVP_PKEY_get_bits(pkey)
}

func EVP_CIPHER_get_block_size(cipher EVP_CIPHER_PTR) int32 {
	if vMajor == 1 {
		return _EVP_CIPHER_block_size(cipher)
	}
	return _EVP_CIPHER_get_block_size(cipher)
}
