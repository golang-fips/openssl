//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"runtime"
	"unsafe"
)

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}
	pkey, err := generateEVPPKey(_EVP_PKEY_RSA, bits, "")
	if err != nil {
		return bad(err)
	}
	defer C.go_openssl_EVP_PKEY_free(pkey)
	switch vMajor {
	case 1:
		key := C.go_openssl_EVP_PKEY_get1_RSA(pkey)
		if key == nil {
			return bad(newOpenSSLError("EVP_PKEY_get1_RSA failed"))
		}
		defer C.go_openssl_RSA_free(key)
		var n, e, d, p, q, dmp1, dmq1, iqmp C.GO_BIGNUM_PTR
		C.go_openssl_RSA_get0_key(key, &n, &e, &d)
		C.go_openssl_RSA_get0_factors(key, &p, &q)
		C.go_openssl_RSA_get0_crt_params(key, &dmp1, &dmq1, &iqmp)
		N, E, D = bnToBig(n), bnToBig(e), bnToBig(d)
		P, Q = bnToBig(p), bnToBig(q)
		Dp, Dq, Qinv = bnToBig(dmp1), bnToBig(dmq1), bnToBig(iqmp)
	case 3:
		tmp := C.go_openssl_BN_new()
		if tmp == nil {
			return bad(newOpenSSLError("BN_new failed"))
		}
		defer func() {
			C.go_openssl_BN_clear_free(tmp)
		}()
		var err error
		setBigInt := func(bi *BigInt, param cString) bool {
			if err != nil {
				return false
			}
			if C.go_openssl_EVP_PKEY_get_bn_param(pkey, param.ptr(), &tmp) != 1 {
				err = newOpenSSLError("EVP_PKEY_get_bn_param failed")
				return false
			}
			*bi = bnToBig(tmp)
			C.go_openssl_BN_clear(tmp)
			return true
		}
		if !(setBigInt(&N, _OSSL_PKEY_PARAM_RSA_N) &&
			setBigInt(&E, _OSSL_PKEY_PARAM_RSA_E) &&
			setBigInt(&D, _OSSL_PKEY_PARAM_RSA_D) &&
			setBigInt(&P, _OSSL_PKEY_PARAM_RSA_FACTOR1) &&
			setBigInt(&Q, _OSSL_PKEY_PARAM_RSA_FACTOR2) &&
			setBigInt(&Dp, _OSSL_PKEY_PARAM_RSA_EXPONENT1) &&
			setBigInt(&Dq, _OSSL_PKEY_PARAM_RSA_EXPONENT2) &&
			setBigInt(&Qinv, _OSSL_PKEY_PARAM_RSA_COEFFICIENT1)) {
			return bad(err)
		}
	default:
		panic(errUnsupportedVersion())
	}
	return
}

type PublicKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey C.GO_EVP_PKEY_PTR
}

func NewPublicKeyRSA(n, e BigInt) (*PublicKeyRSA, error) {
	var pkey C.GO_EVP_PKEY_PTR
	switch vMajor {
	case 1:
		key := C.go_openssl_RSA_new()
		if key == nil {
			return nil, newOpenSSLError("RSA_new failed")
		}
		if C.go_openssl_RSA_set0_key(key, bigToBN(n), bigToBN(e), nil) != 1 {
			return nil, fail("RSA_set0_key")
		}
		pkey = C.go_openssl_EVP_PKEY_new()
		if pkey == nil {
			C.go_openssl_RSA_free(key)
			return nil, newOpenSSLError("EVP_PKEY_new failed")
		}
		if C.go_openssl_EVP_PKEY_assign(pkey, _EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
			C.go_openssl_RSA_free(key)
			C.go_openssl_EVP_PKEY_free(pkey)
			return nil, newOpenSSLError("EVP_PKEY_assign failed")
		}
	case 3:
		var err error
		if pkey, err = newRSAKey3(false, n, e, nil, nil, nil, nil, nil, nil); err != nil {
			return nil, err
		}
	default:
		panic(errUnsupportedVersion())
	}
	k := &PublicKeyRSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PublicKeyRSA).finalize)
	return k, nil
}

func (k *PublicKeyRSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyRSA) withKey(f func(C.GO_EVP_PKEY_PTR) C.int) C.int {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PrivateKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey C.GO_EVP_PKEY_PTR
}

func NewPrivateKeyRSA(n, e, d, p, q, dp, dq, qinv BigInt) (*PrivateKeyRSA, error) {
	var pkey C.GO_EVP_PKEY_PTR
	switch vMajor {
	case 1:
		key := C.go_openssl_RSA_new()
		if key == nil {
			return nil, newOpenSSLError("RSA_new failed")
		}
		if C.go_openssl_RSA_set0_key(key, bigToBN(n), bigToBN(e), bigToBN(d)) != 1 {
			return nil, fail("RSA_set0_key")
		}
		if p != nil && q != nil {
			if C.go_openssl_RSA_set0_factors(key, bigToBN(p), bigToBN(q)) != 1 {
				return nil, fail("RSA_set0_factors")
			}
		}
		if dp != nil && dq != nil && qinv != nil {
			if C.go_openssl_RSA_set0_crt_params(key, bigToBN(dp), bigToBN(dq), bigToBN(qinv)) != 1 {
				return nil, fail("RSA_set0_crt_params")
			}
		}
		pkey = C.go_openssl_EVP_PKEY_new()
		if pkey == nil {
			C.go_openssl_RSA_free(key)
			return nil, newOpenSSLError("EVP_PKEY_new failed")
		}
		if C.go_openssl_EVP_PKEY_assign(pkey, _EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
			C.go_openssl_RSA_free(key)
			C.go_openssl_EVP_PKEY_free(pkey)
			return nil, newOpenSSLError("EVP_PKEY_assign failed")
		}
	case 3:
		var err error
		if pkey, err = newRSAKey3(true, n, e, d, p, q, dp, dq, qinv); err != nil {
			return nil, err
		}
	default:
		panic(errUnsupportedVersion())
	}
	k := &PrivateKeyRSA{_pkey: pkey}
	runtime.SetFinalizer(k, (*PrivateKeyRSA).finalize)
	return k, nil
}

func (k *PrivateKeyRSA) finalize() {
	C.go_openssl_EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyRSA) withKey(f func(C.GO_EVP_PKEY_PTR) C.int) C.int {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, _RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, _RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, msg)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, _RSA_PKCS1_PADDING, nil, nil, nil, ciphertext)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, _RSA_PKCS1_PADDING, nil, nil, nil, msg)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	ret, err := evpDecrypt(priv.withKey, _RSA_NO_PADDING, nil, nil, nil, ciphertext)
	if err != nil {
		return nil, err
	}
	// We could return here, but the Go standard library test expects DecryptRSANoPadding to verify the result
	// in order to defend against errors in the CRT computation.
	//
	// The following code tries to replicate the verification implemented in the upstream function decryptAndCheck, found at
	// https://github.com/golang/go/blob/9de1ac6ac2cad3871760d0aa288f5ca713afd0a6/src/crypto/rsa/rsa.go#L569-L582.
	pub := &PublicKeyRSA{_pkey: priv._pkey}
	// A private EVP_PKEY can be used as a public key as it contains the public information.
	enc, err := EncryptRSANoPadding(pub, ret)
	if err != nil {
		return nil, err
	}
	// Upstream does not do a constant time comparison because it works with math/big instead of byte slices,
	// and math/big does not support constant-time arithmetic yet. See #20654 for more info.
	if subtle.ConstantTimeCompare(ciphertext, enc) != 1 {
		return nil, errors.New("rsa: internal error")
	}
	return ret, nil
}

func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, _RSA_NO_PADDING, nil, nil, nil, msg)
}

func saltLength(saltLen int, sign bool) (C.int, error) {
	// A salt length of -2 is valid in OpenSSL, but not in crypto/rsa, so reject
	// it, and lengths < -2, before we convert to the OpenSSL sentinel values.
	if saltLen <= -2 {
		return 0, errors.New("crypto/rsa: invalid PSS salt length")
	}
	// OpenSSL uses sentinel salt length values like Go crypto does,
	// but the values don't fully match for rsa.PSSSaltLengthAuto (0).
	if saltLen == 0 {
		if sign {
			if vMajor == 1 {
				// OpenSSL 1.x uses -2 to mean maximal size when signing where Go crypto uses 0.
				return _RSA_PSS_SALTLEN_MAX_SIGN, nil
			}
			// OpenSSL 3.x deprecated RSA_PSS_SALTLEN_MAX_SIGN
			// and uses -3 to mean maximal size when signing where Go crypto uses 0.
			return _RSA_PSS_SALTLEN_MAX, nil
		}
		// OpenSSL uses -2 to mean auto-detect size when verifying where Go crypto uses 0.
		return _RSA_PSS_SALTLEN_AUTO, nil
	}
	return C.int(saltLen), nil
}

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	cSaltLen, err := saltLength(saltLen, true)
	if err != nil {
		return nil, err
	}
	return evpSign(priv.withKey, _RSA_PKCS1_PSS_PADDING, cSaltLen, h, hashed)
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	cSaltLen, err := saltLength(saltLen, false)
	if err != nil {
		return err
	}
	return evpVerify(pub.withKey, _RSA_PKCS1_PSS_PADDING, cSaltLen, h, sig, hashed)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, _RSA_PKCS1_PADDING, 0, h, hashed)
}

func HashSignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, msg []byte) ([]byte, error) {
	return evpHashSign(priv.withKey, h, msg)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	if pub.withKey(func(pkey C.GO_EVP_PKEY_PTR) C.int {
		size := C.go_openssl_EVP_PKEY_get_size(pkey)
		if len(sig) < int(size) {
			return 0
		}
		return 1
	}) == 0 {
		return errors.New("crypto/rsa: verification error")
	}
	return evpVerify(pub.withKey, _RSA_PKCS1_PADDING, 0, h, sig, hashed)
}

func HashVerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, msg, sig []byte) error {
	return evpHashVerify(pub.withKey, h, msg, sig)
}

func newRSAKey3(isPriv bool, n, e, d, p, q, dp, dq, qinv BigInt) (C.GO_EVP_PKEY_PTR, error) {
	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()

	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_N, n, false)
	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_E, e, false)
	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_D, d, false)

	if p != nil && q != nil {
		allPrecomputedExists := dp != nil && dq != nil && qinv != nil
		// The precomputed values should only be passed if P and Q are present
		// and every precomputed value is present. (If any precomputed value is
		// missing, don't pass any of them.)
		//
		// In OpenSSL 3.0 and 3.1, we must also omit P and Q if any precomputed
		// value is missing. See https://github.com/openssl/openssl/pull/22334
		if vMinor >= 2 || allPrecomputedExists {
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_FACTOR1, p, true)
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_FACTOR2, q, true)
		}
		if allPrecomputedExists {
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_EXPONENT1, dp, true)
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_EXPONENT2, dq, true)
			bld.addBigInt(_OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qinv, true)
		}
	}

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer C.go_openssl_OSSL_PARAM_free(params)
	selection := _EVP_PKEY_PUBLIC_KEY
	if isPriv {
		selection = _EVP_PKEY_KEYPAIR
	}
	return newEvpFromParams(_EVP_PKEY_RSA, C.int(selection), params)
}
