//go:build !cmd_go_bootstrap

package openssl

import (
	"errors"
	"strconv"
	"sync"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

func SupportsCurve(curve string) bool {
	switch curve {
	case "P-224", "P-256", "P-384", "P-521":
		return true
	case "X25519":
		return supportsX25519()
	default:
		return false
	}
}

var supportsX25519 = sync.OnceValue(func() bool {
	if !versionAtOrAbove(1, 1, 1) {
		// X25519 support was added in OpenSSL 1.1.0, but the APIs we use
		// to implement it were only added in 1.1.1.
		return false
	}
	ctx, _ := ossl.EVP_PKEY_CTX_new_id(ossl.EVP_PKEY_X25519, nil)
	if ctx != nil {
		ossl.EVP_PKEY_CTX_free(ctx)
		return true
	}
	return false
})

func curveID(curve string) int32 {
	switch curve {
	case "P-224":
		return ossl.EVP_PKEY_EC
	case "P-256":
		return ossl.EVP_PKEY_EC
	case "P-384":
		return ossl.EVP_PKEY_EC
	case "P-521":
		return ossl.EVP_PKEY_EC
	case "X25519":
		return ossl.EVP_PKEY_X25519
	default:
		panic("openssl: unknown curve " + curve)
	}
}

func curveNID(curve string) int32 {
	switch curve {
	case "P-224":
		return ossl.NID_secp224r1
	case "P-256":
		return ossl.NID_X9_62_prime256v1
	case "P-384":
		return ossl.NID_secp384r1
	case "P-521":
		return ossl.NID_secp521r1
	default:
		panic("openssl: unknown curve " + curve)
	}
}

// curveSize returns the size of the curve in bytes.
func curveSize(curve string) int {
	switch curve {
	case "P-224":
		return 224 / 8
	case "P-256":
		return 256 / 8
	case "P-384":
		return 384 / 8
	case "P-521":
		return (521 + 7) / 8
	default:
		panic("openssl: unknown curve " + curve)
	}
}

// encodeEcPoint encodes pt.
func encodeEcPoint(group ossl.EC_GROUP_PTR, pt ossl.EC_POINT_PTR) ([]byte, error) {
	// Get encoded point size.
	n, err := ossl.EC_POINT_point2oct(group, pt, ossl.POINT_CONVERSION_UNCOMPRESSED, nil, 0, nil)
	if err != nil {
		return nil, err
	}
	// Encode point into bytes.
	bytes := make([]byte, n)
	if _, err = ossl.EC_POINT_point2oct(group, pt, ossl.POINT_CONVERSION_UNCOMPRESSED, base(bytes), n, nil); err != nil {
		return nil, err
	}
	return bytes, nil
}

// generateAndEncodeEcPublicKey calls newPubKeyPointFn to generate a public key point and then encodes it.
func generateAndEncodeEcPublicKey(nid int32, newPubKeyPointFn func(group ossl.EC_GROUP_PTR) (ossl.EC_POINT_PTR, error)) ([]byte, error) {
	group, err := ossl.EC_GROUP_new_by_curve_name(nid)
	if err != nil {
		return nil, err
	}
	defer ossl.EC_GROUP_free(group)
	pt, err := newPubKeyPointFn(group)
	if err != nil {
		return nil, err
	}
	defer ossl.EC_POINT_free(pt)
	return encodeEcPoint(group, pt)
}

func extractPKEYRawPublic(pkey ossl.EVP_PKEY_PTR, pub []byte) error {
	keylen := len(pub)
	if _, err := ossl.EVP_PKEY_get_raw_public_key(pkey, base(pub), &keylen); err != nil {
		return err
	}
	if keylen != len(pub) {
		return errors.New("bad public key length: " + strconv.Itoa(keylen))
	}
	return nil
}

func extractPKEYRawPrivate(pkey ossl.EVP_PKEY_PTR, pub []byte) error {
	keylen := len(pub)
	if _, err := ossl.EVP_PKEY_get_raw_private_key(pkey, base(pub), &keylen); err != nil {
		return err
	}
	if keylen != len(pub) {
		return errors.New("bad private key length: " + strconv.Itoa(keylen))
	}
	return nil
}
