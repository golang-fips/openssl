//go:build !cgo

package ossl

import (
	"errors"
	"unsafe"
)

// goString converts a C string (byte pointer) to a Go string
func goString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var result []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + i))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}

// Variadic wrapper functions for nocgo mode
// These functions wrap the base variadic function EVP_PKEY_Q_keygen
func EVP_PKEY_Q_keygen_RSA(ctx OSSL_LIB_CTX_PTR, propq *byte, keytype *byte, bits int) (EVP_PKEY_PTR, error) {
	// For nocgo mode, implement using the traditional approach
	pctx, err := EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil)
	if err != nil {
		return nil, err
	}
	defer EVP_PKEY_CTX_free(pctx)

	if _, err := EVP_PKEY_keygen_init(pctx); err != nil {
		return nil, err
	}

	if _, err := EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, int32(bits), nil); err != nil {
		return nil, err
	}

	var pkey EVP_PKEY_PTR
	if _, err := EVP_PKEY_keygen(pctx, &pkey); err != nil {
		return nil, err
	}

	return pkey, nil
}

func EVP_PKEY_Q_keygen_EC(ctx OSSL_LIB_CTX_PTR, propq *byte, keytype *byte, curveName *byte) (EVP_PKEY_PTR, error) {
	// For nocgo mode, implement using the traditional approach
	pctx, err := EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil)
	if err != nil {
		return nil, err
	}
	defer EVP_PKEY_CTX_free(pctx)

	if _, err := EVP_PKEY_keygen_init(pctx); err != nil {
		return nil, err
	}

	// Convert curve name to NID - this is a simple approach
	// In a real implementation, you'd need to properly map curve names to NIDs
	var nid int32
	curveStr := goString(curveName)
	switch curveStr {
	case "prime256v1", "secp256r1":
		nid = NID_X9_62_prime256v1
	case "secp224r1":
		nid = NID_secp224r1
	case "secp384r1":
		nid = NID_secp384r1
	case "secp521r1":
		nid = NID_secp521r1
	default:
		return nil, errors.New("unsupported curve: " + curveStr)
	}

	if _, err := EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, nil); err != nil {
		return nil, err
	}

	var pkey EVP_PKEY_PTR
	if _, err := EVP_PKEY_keygen(pctx, &pkey); err != nil {
		return nil, err
	}

	return pkey, nil
}

func EVP_PKEY_Q_keygen_ED25519(ctx OSSL_LIB_CTX_PTR, propq *byte, keytype *byte) (EVP_PKEY_PTR, error) {
	// For nocgo mode, implement using the traditional approach
	pctx, err := EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nil)
	if err != nil {
		return nil, err
	}
	defer EVP_PKEY_CTX_free(pctx)

	if _, err := EVP_PKEY_keygen_init(pctx); err != nil {
		return nil, err
	}

	var pkey EVP_PKEY_PTR
	if _, err := EVP_PKEY_keygen(pctx, &pkey); err != nil {
		return nil, err
	}

	return pkey, nil
}
