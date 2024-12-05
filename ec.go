//go:build !cmd_go_bootstrap && cgo

package openssl

import "github.com/golang-fips/openssl/v2/internal/ossl"

func curveNID(curve string) (int, error) {
	switch curve {
	case "P-224":
		return ossl.NID_secp224r1, nil
	case "P-256":
		return ossl.NID_X9_62_prime256v1, nil
	case "P-384":
		return ossl.NID_secp384r1, nil
	case "P-521":
		return ossl.NID_secp521r1, nil
	}
	return 0, errUnknownCurve
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
	n, err = ossl.EC_POINT_point2oct(group, pt, ossl.POINT_CONVERSION_UNCOMPRESSED, base(bytes), n, nil)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// generateAndEncodeEcPublicKey calls newPubKeyPointFn to generate a public key point and then encodes it.
func generateAndEncodeEcPublicKey(nid int, newPubKeyPointFn func(group ossl.EC_GROUP_PTR) (ossl.EC_POINT_PTR, error)) ([]byte, error) {
	group, err := ossl.EC_GROUP_new_by_curve_name(int32(nid))
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
