//go:build cgo

package ossl

//go:generate go run github.com/golang-fips/openssl/v2/internal/mkcgo -out zossl.go --package ossl --lib crypto --include ossl.h api.h
