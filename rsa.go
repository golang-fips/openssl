//go:build linux && !android
// +build linux,!android

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

var (
	paramRSA_N    = C.CString("n")
	paramRSA_E    = C.CString("e")
	paramRSA_D    = C.CString("d")
	paramRSA_P    = C.CString("rsa-factor1")
	paramRSA_Q    = C.CString("rsa-factor2")
	paramRSA_Dp   = C.CString("rsa-exponent1")
	paramRSA_Dq   = C.CString("rsa-exponent2")
	paramRSA_Qinv = C.CString("rsa-coefficient1")
)

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}
	pkey, err := generateEVPPKey(C.GO_EVP_PKEY_RSA, bits, "")
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
		if vMinor == 0 {
			r := (*rsa_st_1_0_2)(unsafe.Pointer(key))
			n, e, d, p, q, dmp1, dmq1, iqmp = r.n, r.e, r.d, r.p, r.q, r.dmp1, r.dmq1, r.iqmp
		} else {
			C.go_openssl_RSA_get0_key(key, &n, &e, &d)
			C.go_openssl_RSA_get0_factors(key, &p, &q)
			C.go_openssl_RSA_get0_crt_params(key, &dmp1, &dmq1, &iqmp)
		}
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
		setBigInt := func(bi *BigInt, param *C.char) bool {
			if err != nil {
				return false
			}
			if C.go_openssl_EVP_PKEY_get_bn_param(pkey, param, &tmp) != 1 {
				err = newOpenSSLError("EVP_PKEY_get_bn_param failed")
				return false
			}
			*bi = bnToBig(tmp)
			C.go_openssl_BN_clear(tmp)
			return true
		}
		if !(setBigInt(&N, paramRSA_N) &&
			setBigInt(&E, paramRSA_E) &&
			setBigInt(&D, paramRSA_D) &&
			setBigInt(&P, paramRSA_P) &&
			setBigInt(&Q, paramRSA_Q) &&
			setBigInt(&Dp, paramRSA_Dp) &&
			setBigInt(&Dq, paramRSA_Dq) &&
			setBigInt(&Qinv, paramRSA_Qinv)) {
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

func NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error) {
	var pkey C.GO_EVP_PKEY_PTR
	switch vMajor {
	case 1:
		key := C.go_openssl_RSA_new()
		if key == nil {
			return nil, newOpenSSLError("RSA_new failed")
		}
		if !rsaSetKey(key, N, E, nil) {
			return nil, fail("RSA_set0_key")
		}
		pkey = C.go_openssl_EVP_PKEY_new()
		if pkey == nil {
			C.go_openssl_RSA_free(key)
			return nil, newOpenSSLError("EVP_PKEY_new failed")
		}
		if C.go_openssl_EVP_PKEY_assign(pkey, C.GO_EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
			C.go_openssl_RSA_free(key)
			C.go_openssl_EVP_PKEY_free(pkey)
			return nil, newOpenSSLError("EVP_PKEY_assign failed")
		}
	case 3:
		var err error
		if pkey, err = newRSAKey3(false, N, E, nil, nil, nil, nil, nil, nil); err != nil {
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

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error) {
	var pkey C.GO_EVP_PKEY_PTR
	switch vMajor {
	case 1:
		key := C.go_openssl_RSA_new()
		if key == nil {
			return nil, newOpenSSLError("RSA_new failed")
		}
		if !rsaSetKey(key, N, E, D) {
			return nil, fail("RSA_set0_key")
		}
		if P != nil && Q != nil {
			if !rsaSetFactors(key, P, Q) {
				return nil, fail("RSA_set0_factors")
			}
		}
		if Dp != nil && Dq != nil && Qinv != nil {
			if !rsaSetCRTParams(key, Dp, Dq, Qinv) {
				return nil, fail("RSA_set0_crt_params")
			}
		}
		pkey = C.go_openssl_EVP_PKEY_new()
		if pkey == nil {
			C.go_openssl_RSA_free(key)
			return nil, newOpenSSLError("EVP_PKEY_new failed")
		}
		if C.go_openssl_EVP_PKEY_assign(pkey, C.GO_EVP_PKEY_RSA, (unsafe.Pointer)(key)) != 1 {
			C.go_openssl_RSA_free(key)
			C.go_openssl_EVP_PKEY_free(pkey)
			return nil, newOpenSSLError("EVP_PKEY_assign failed")
		}
	case 3:
		var err error
		if pkey, err = newRSAKey3(true, N, E, D, P, Q, Dp, Dq, Qinv); err != nil {
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
	return evpDecrypt(priv.withKey, C.GO_RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, C.GO_RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, msg)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, C.GO_RSA_PKCS1_PADDING, nil, nil, nil, ciphertext)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, C.GO_RSA_PKCS1_PADDING, nil, nil, nil, msg)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	ret, err := evpDecrypt(priv.withKey, C.GO_RSA_NO_PADDING, nil, nil, nil, ciphertext)
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
	return evpEncrypt(pub.withKey, C.GO_RSA_NO_PADDING, nil, nil, nil, msg)
}

func saltLength(saltLen int, sign bool) (C.int, error) {
	// A salt length of -2 is valid in OpenSSL, but not in crypto/rsa, so reject
	// it, and lengths < -2, before we convert to the OpenSSL sentinel values.
	if saltLen <= -2 {
		return 0, errors.New("crypto/rsa: PSSOptions.SaltLength cannot be negative")
	}
	// OpenSSL uses sentinel salt length values like Go crypto does,
	// but the values don't fully match for rsa.PSSSaltLengthAuto (0).
	if saltLen == 0 {
		if sign {
			if vMajor == 1 {
				// OpenSSL 1.x uses -2 to mean maximal size when signing where Go crypto uses 0.
				return C.GO_RSA_PSS_SALTLEN_MAX_SIGN, nil
			}
			// OpenSSL 3.x deprecated RSA_PSS_SALTLEN_MAX_SIGN
			// and uses -3 to mean maximal size when signing where Go crypto uses 0.
			return C.GO_RSA_PSS_SALTLEN_MAX, nil
		}
		// OpenSSL uses -2 to mean auto-detect size when verifying where Go crypto uses 0.
		return C.GO_RSA_PSS_SALTLEN_AUTO, nil
	}
	return C.int(saltLen), nil
}

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	cSaltLen, err := saltLength(saltLen, true)
	if err != nil {
		return nil, err
	}
	return evpSign(priv.withKey, C.GO_RSA_PKCS1_PSS_PADDING, cSaltLen, h, hashed)
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	cSaltLen, err := saltLength(saltLen, false)
	if err != nil {
		return err
	}
	return evpVerify(pub.withKey, C.GO_RSA_PKCS1_PSS_PADDING, cSaltLen, h, sig, hashed)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, C.GO_RSA_PKCS1_PADDING, 0, h, hashed)
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
	return evpVerify(pub.withKey, C.GO_RSA_PKCS1_PADDING, 0, h, sig, hashed)
}

func HashVerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, msg, sig []byte) error {
	return evpHashVerify(pub.withKey, h, msg, sig)
}

// rsa_st_1_0_2 is rsa_st memory layout in OpenSSL 1.0.2.
type rsa_st_1_0_2 struct {
	_                C.int
	_                C.long
	_                [2]unsafe.Pointer
	n, e, d          C.GO_BIGNUM_PTR
	p, q             C.GO_BIGNUM_PTR
	dmp1, dmq1, iqmp C.GO_BIGNUM_PTR
	// It contains more fields, but we are not interesed on them.
}

func bnSet(b1 *C.GO_BIGNUM_PTR, b2 BigInt) {
	if b2 == nil {
		return
	}
	if *b1 != nil {
		C.go_openssl_BN_clear_free(*b1)
	}
	*b1 = bigToBN(b2)
}

func rsaSetKey(key C.GO_RSA_PTR, n, e, d BigInt) bool {
	if vMajor == 1 && vMinor == 0 {
		r := (*rsa_st_1_0_2)(unsafe.Pointer(key))
		//r.d and d will be nil for public keys.
		if (r.n == nil && n == nil) ||
			(r.e == nil && e == nil) {
			return false
		}
		bnSet(&r.n, n)
		bnSet(&r.e, e)
		bnSet(&r.d, d)
		return true
	}
	return C.go_openssl_RSA_set0_key(key, bigToBN(n), bigToBN(e), bigToBN(d)) == 1
}

func rsaSetFactors(key C.GO_RSA_PTR, p, q BigInt) bool {
	if vMajor == 1 && vMinor == 0 {
		r := (*rsa_st_1_0_2)(unsafe.Pointer(key))
		if (r.p == nil && p == nil) ||
			(r.q == nil && q == nil) {
			return false
		}
		bnSet(&r.p, p)
		bnSet(&r.q, q)
		return true
	}
	return C.go_openssl_RSA_set0_factors(key, bigToBN(p), bigToBN(q)) == 1
}

func rsaSetCRTParams(key C.GO_RSA_PTR, dmp1, dmq1, iqmp BigInt) bool {
	if vMajor == 1 && vMinor == 0 {
		r := (*rsa_st_1_0_2)(unsafe.Pointer(key))
		if (r.dmp1 == nil && dmp1 == nil) ||
			(r.dmq1 == nil && dmq1 == nil) ||
			(r.iqmp == nil && iqmp == nil) {
			return false
		}
		bnSet(&r.dmp1, dmp1)
		bnSet(&r.dmq1, dmq1)
		bnSet(&r.iqmp, iqmp)
		return true
	}
	return C.go_openssl_RSA_set0_crt_params(key, bigToBN(dmp1), bigToBN(dmq1), bigToBN(iqmp)) == 1
}

func newRSAKey3(isPriv bool, N, E, D, P, Q, Dp, Dq, Qinv BigInt) (C.GO_EVP_PKEY_PTR, error) {
	// Construct the parameters.
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	defer C.go_openssl_OSSL_PARAM_BLD_free(bld)
	var comps = [...]struct {
		name *C.char
		num  BigInt
	}{
		{paramRSA_N, N}, {paramRSA_E, E}, {paramRSA_D, D},
		{paramRSA_P, P}, {paramRSA_Q, Q},
		{paramRSA_Dp, Dp}, {paramRSA_Dq, Dq}, {paramRSA_Qinv, Qinv},
	}
	for _, comp := range comps {
		if comp.num == nil {
			continue
		}
		b := bigToBN(comp.num)
		if b == nil {
			return nil, newOpenSSLError("BN_lebin2bn failed")
		}
		// b must remain valid until OSSL_PARAM_BLD_to_param has been called.
		defer C.go_openssl_BN_clear_free(b)
		if C.go_openssl_OSSL_PARAM_BLD_push_BN(bld, comp.name, b) != 1 {
			return nil, newOpenSSLError("OSSL_PARAM_BLD_push_BN")
		}
	}
	params := C.go_openssl_OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return nil, newOpenSSLError("OSSL_PARAM_BLD_to_param")
	}
	defer C.go_openssl_OSSL_PARAM_free(params)
	selection := C.GO_EVP_PKEY_PUBLIC_KEY
	if isPriv {
		selection = C.GO_EVP_PKEY_KEYPAIR
	}
	return newEvpFromParams(C.GO_EVP_PKEY_RSA, C.int(selection), params)
}
