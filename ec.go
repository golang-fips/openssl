//go:build linux

package openssl

// #include "goopenssl.h"
import "C"

var (
	paramPubKey  = C.CString("pub")
	paramPrivKey = C.CString("priv")
	paramGroup   = C.CString("group")
	paramECPubX  = C.CString("qx")
	paramECPubY  = C.CString("qy")
)

func curveNID(curve string) (C.int, error) {
	switch curve {
	case "P-224":
		return C.GO_NID_secp224r1, nil
	case "P-256":
		return C.GO_NID_X9_62_prime256v1, nil
	case "P-384":
		return C.GO_NID_secp384r1, nil
	case "P-521":
		return C.GO_NID_secp521r1, nil
	}
	return 0, errUnknownCurve
}

// encodeEcPoint encodes pt.
func encodeEcPoint(group C.GO_EC_GROUP_PTR, pt C.GO_EC_POINT_PTR) ([]byte, error) {
	// Get encoded point size.
	n := C.go_openssl_EC_POINT_point2oct(group, pt, C.GO_POINT_CONVERSION_UNCOMPRESSED, nil, 0, nil)
	if n == 0 {
		return nil, newOpenSSLError("EC_POINT_point2oct")
	}
	// Encode point into bytes.
	bytes := make([]byte, n)
	n = C.go_openssl_EC_POINT_point2oct(group, pt, C.GO_POINT_CONVERSION_UNCOMPRESSED, base(bytes), n, nil)
	if n == 0 {
		return nil, newOpenSSLError("EC_POINT_point2oct")
	}
	return bytes, nil
}

// generateAndEncodeEcPublicKey calls newPubKeyPointFn to generate a public key point and then encodes it.
func generateAndEncodeEcPublicKey(nid C.int, newPubKeyPointFn func(group C.GO_EC_GROUP_PTR) (C.GO_EC_POINT_PTR, error)) ([]byte, error) {
	group := C.go_openssl_EC_GROUP_new_by_curve_name(nid)
	if group == nil {
		return nil, newOpenSSLError("EC_GROUP_new_by_curve_name")
	}
	defer C.go_openssl_EC_GROUP_free(group)
	pt, err := newPubKeyPointFn(group)
	if err != nil {
		return nil, err
	}
	defer C.go_openssl_EC_POINT_free(pt)
	return encodeEcPoint(group, pt)
}
