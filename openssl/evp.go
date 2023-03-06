//go:build linux && !android && !cmd_go_bootstrap && !msan && !no_openssl
// +build linux,!android,!cmd_go_bootstrap,!msan,!no_openssl

package openssl

// #include "goopenssl.h"
import "C"

func generateEVPPKey(id C.int, bits int, curve string) (*C.GO_EVP_PKEY, error) {
	if (bits == 0 && curve == "") || (bits != 0 && curve != "") {
		return nil, fail("incorrect generateEVPPKey parameters")
	}
	ctx := C._goboringcrypto_EVP_PKEY_CTX_new_id(id, nil)
	if ctx == nil {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_new_id failed")
	}
	defer C._goboringcrypto_EVP_PKEY_CTX_free(ctx)
	if C._goboringcrypto_EVP_PKEY_keygen_init(ctx) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_keygen_init failed")
	}
	if bits != 0 {
		if C._goboringcrypto_EVP_PKEY_CTX_ctrl(ctx, id, -1, C.GO_EVP_PKEY_CTRL_RSA_KEYGEN_BITS, C.int(bits), nil) != 1 {
			return nil, NewOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
	}
	if curve != "" {
		nid, err := curveNID(curve)
		if err != nil {
			return nil, err
		}
		if C._goboringcrypto_EVP_PKEY_CTX_ctrl(ctx, id, -1, C.GO_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, nil) != 1 {
			return nil, NewOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
	}
	var pkey *C.GO_EVP_PKEY
	if C._goboringcrypto_EVP_PKEY_keygen(ctx, &pkey) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_keygen failed")
	}
	return pkey, nil
}

// getECKey returns the EC_KEY from pkey.
// If pkey does not contain an EC_KEY it panics.
// The returned key should not be freed.
func getECKey(pkey *C.GO_EVP_PKEY) (key *C.GO_EC_KEY) {
	key = C._goboringcrypto_EVP_PKEY_get0_EC_KEY(pkey)
	if key == nil {
		panic("pkey does not contain an EC_KEY")
	}
	return key
}
