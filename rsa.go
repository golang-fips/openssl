//go:build !cmd_go_bootstrap

package openssl

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"hash"
	"runtime"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}
	pkey, err := generateEVPPKey(ossl.EVP_PKEY_RSA, int32(bits), "")
	if err != nil {
		return bad(err)
	}
	defer ossl.EVP_PKEY_free(pkey)
	switch major() {
	case 1:
		key, err := ossl.EVP_PKEY_get1_RSA(pkey)
		if err != nil {
			return bad(err)
		}
		defer ossl.RSA_free(key)
		var n, e, d, p, q, dmp1, dmq1, iqmp ossl.BIGNUM_PTR
		ossl.RSA_get0_key(key, &n, &e, &d)
		ossl.RSA_get0_factors(key, &p, &q)
		ossl.RSA_get0_crt_params(key, &dmp1, &dmq1, &iqmp)
		N, E, D = bnToBig(n), bnToBig(e), bnToBig(d)
		P, Q = bnToBig(p), bnToBig(q)
		Dp, Dq, Qinv = bnToBig(dmp1), bnToBig(dmq1), bnToBig(iqmp)
	case 3:
		tmp, err := ossl.BN_new()
		if err != nil {
			return bad(err)
		}
		defer func() {
			ossl.BN_clear_free(tmp)
		}()
		setBigInt := func(bi *BigInt, param cString) bool {
			if err != nil {
				return false
			}
			if _, err = ossl.EVP_PKEY_get_bn_param(pkey, param.ptr(), &tmp); err != nil {
				return false
			}
			*bi = bnToBig(tmp)
			ossl.BN_clear(tmp)
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
	_pkey ossl.EVP_PKEY_PTR
}

func NewPublicKeyRSA(n, e BigInt) (*PublicKeyRSA, error) {
	var pkey ossl.EVP_PKEY_PTR
	switch major() {
	case 1:
		key, err := ossl.RSA_new()
		if err != nil {
			return nil, err
		}
		// No need to check for errors here, RSA_set0_* functions will fail
		// if the BNs are NULL and we will free non-NULL BNs in the error handling.
		bn, _ := bigToBN(n)
		be, _ := bigToBN(e)
		if _, err := ossl.RSA_set0_key(key, bn, be, nil); err != nil {
			ossl.BN_free(bn)
			ossl.BN_free(be)
			ossl.RSA_free(key)
			return nil, err
		}
		pkey, err = ossl.EVP_PKEY_new()
		if err != nil {
			ossl.RSA_free(key)
			return nil, err
		}
		if _, err := ossl.EVP_PKEY_assign(pkey, ossl.EVP_PKEY_RSA, (unsafe.Pointer)(key)); err != nil {
			ossl.RSA_free(key)
			ossl.EVP_PKEY_free(pkey)
			return nil, err
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
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PublicKeyRSA) withKey(f func(ossl.EVP_PKEY_PTR) error) error {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PrivateKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey ossl.EVP_PKEY_PTR
}

func NewPrivateKeyRSA(n, e, d, p, q, dp, dq, qinv BigInt) (*PrivateKeyRSA, error) {
	var pkey ossl.EVP_PKEY_PTR
	switch major() {
	case 1:
		key, err := ossl.RSA_new()
		if err != nil {
			return nil, err
		}
		// No need to check for errors here, RSA_set0_* functions will fail
		// if the BNs are NULL and we will free non-NULL BNs in the error handling.
		bn, _ := bigToBN(n)
		be, _ := bigToBN(e)
		bd, _ := bigToBN(d)
		if _, err := ossl.RSA_set0_key(key, bn, be, bd); err != nil {
			ossl.BN_free(bn)
			ossl.BN_free(be)
			ossl.BN_clear_free(bd)
			return nil, err
		}
		if p != nil && q != nil {
			bp, _ := bigToBN(p)
			bq, _ := bigToBN(q)
			if _, err := ossl.RSA_set0_factors(key, bp, bq); err != nil {
				ossl.BN_clear_free(bp)
				ossl.BN_clear_free(bq)
				return nil, err
			}
		}
		if dp != nil && dq != nil && qinv != nil {
			bdp, _ := bigToBN(dp)
			bdq, _ := bigToBN(dq)
			bqinv, _ := bigToBN(qinv)
			if _, err := ossl.RSA_set0_crt_params(key, bdp, bdq, bqinv); err != nil {
				ossl.BN_free(bdp)
				ossl.BN_free(bdq)
				ossl.BN_free(bqinv)
				return nil, err
			}
		}
		pkey, err = ossl.EVP_PKEY_new()
		if err != nil {
			ossl.RSA_free(key)
			return nil, err
		}
		if _, err := ossl.EVP_PKEY_assign(pkey, ossl.EVP_PKEY_RSA, (unsafe.Pointer)(key)); err != nil {
			ossl.RSA_free(key)
			ossl.EVP_PKEY_free(pkey)
			return nil, err
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
	ossl.EVP_PKEY_free(k._pkey)
}

func (k *PrivateKeyRSA) withKey(f func(ossl.EVP_PKEY_PTR) error) error {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

func DecryptRSAOAEP(h, mgfHash hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, ossl.RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, ciphertext)
}

func EncryptRSAOAEP(h, mgfHash hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, ossl.RSA_PKCS1_OAEP_PADDING, h, mgfHash, label, msg)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, ossl.RSA_PKCS1_PADDING, nil, nil, nil, ciphertext)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, ossl.RSA_PKCS1_PADDING, nil, nil, nil, msg)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	ret, err := evpDecrypt(priv.withKey, ossl.RSA_NO_PADDING, nil, nil, nil, ciphertext)
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
	return evpEncrypt(pub.withKey, ossl.RSA_NO_PADDING, nil, nil, nil, msg)
}

func saltLength(saltLen int, sign bool) (int32, error) {
	// A salt length of -2 is valid in OpenSSL, but not in crypto/rsa, so reject
	// it, and lengths < -2, before we convert to the OpenSSL sentinel values.
	if saltLen <= -2 {
		return 0, errors.New("crypto/rsa: invalid PSS salt length")
	}
	// OpenSSL uses sentinel salt length values like Go crypto does,
	// but the values don't fully match for rsa.PSSSaltLengthAuto (0).
	if saltLen == 0 {
		if sign {
			if major() == 1 {
				// OpenSSL 1.x uses -2 to mean maximal size when signing where Go crypto uses 0.
				return ossl.RSA_PSS_SALTLEN_MAX_SIGN, nil
			}
			// OpenSSL 3.x deprecated RSA_PSS_SALTLEN_MAX_SIGN
			// and uses -3 to mean maximal size when signing where Go crypto uses 0.
			return ossl.RSA_PSS_SALTLEN_MAX, nil
		}
		// OpenSSL uses -2 to mean auto-detect size when verifying where Go crypto uses 0.
		return ossl.RSA_PSS_SALTLEN_AUTO, nil
	}
	return int32(saltLen), nil
}

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	cSaltLen, err := saltLength(saltLen, true)
	if err != nil {
		return nil, err
	}
	return evpSign(priv.withKey, ossl.RSA_PKCS1_PSS_PADDING, cSaltLen, h, hashed)
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	cSaltLen, err := saltLength(saltLen, false)
	if err != nil {
		return err
	}
	return evpVerify(pub.withKey, ossl.RSA_PKCS1_PSS_PADDING, cSaltLen, h, sig, hashed)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, ossl.RSA_PKCS1_PADDING, 0, h, hashed)
}

func HashSignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, msg []byte) ([]byte, error) {
	return evpHashSign(priv.withKey, h, msg)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	defer runtime.KeepAlive(pub)
	var size int32
	if err := pub.withKey(func(pkey ossl.EVP_PKEY_PTR) (err error) {
		size, err = ossl.EVP_PKEY_get_size(pkey)
		if err != nil {
			return err
		}
		if len(sig) < int(size) {
			return errors.New("crypto/rsa: verification error")
		}
		return nil
	}); err != nil {
		return err
	}
	return evpVerify(pub.withKey, ossl.RSA_PKCS1_PADDING, 0, h, sig, hashed)
}

func HashVerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, msg, sig []byte) error {
	return evpHashVerify(pub.withKey, h, msg, sig)
}

func newRSAKey3(isPriv bool, n, e, d, p, q, dp, dq, qinv BigInt) (ossl.EVP_PKEY_PTR, error) {
	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()

	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_N, n, false)
	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_E, e, false)
	bld.addBigInt(_OSSL_PKEY_PARAM_RSA_D, d, false)

	// OpenSSL 3.0 and 3.1 required all the precomputed values if
	// P and Q are present. See:
	// https://github.com/openssl/openssl/pull/22334
	//
	// We could only set P and Q if they exist when using OpenSSL 3.2
	// or newer, but the RSA provider might be built with an older
	// OpenSSL version, in which case it would still require all the
	// precomputed values. So better always provide all the values or
	// none of them.
	if p != nil && q != nil && dp != nil && dq != nil && qinv != nil {
		bld.addBigInt(_OSSL_PKEY_PARAM_RSA_FACTOR1, p, true)
		bld.addBigInt(_OSSL_PKEY_PARAM_RSA_FACTOR2, q, true)
		bld.addBigInt(_OSSL_PKEY_PARAM_RSA_EXPONENT1, dp, true)
		bld.addBigInt(_OSSL_PKEY_PARAM_RSA_EXPONENT2, dq, true)
		bld.addBigInt(_OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qinv, true)
	}

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)
	selection := ossl.EVP_PKEY_PUBLIC_KEY
	if isPriv {
		selection = ossl.EVP_PKEY_KEYPAIR
	}
	return newEvpFromParams(ossl.EVP_PKEY_RSA, int32(selection), params)
}

// SupportsRSAPKCS1v15Encryption returns true if the RSA PKCS1 v1.5 padding is supported for encryption and decryption.
var SupportsRSAPKCS1v15Encryption = sync.OnceValue(func() bool {
	pkey := testRSAPrivateKey()
	ctx, err := ossl.EVP_PKEY_CTX_new(pkey, nil)
	if err != nil {
		return false
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)

	if _, err := ossl.EVP_PKEY_encrypt_init(ctx); err != nil {
		return false
	}

	if _, err := ossl.EVP_PKEY_CTX_ctrl(ctx, ossl.EVP_PKEY_RSA, -1, ossl.EVP_PKEY_CTRL_RSA_PADDING, ossl.RSA_PKCS1_PADDING, nil); err != nil {
		return false
	}

	// In FIPS mode, setting the padding might succeed, but the actual encryption will fail.
	// So we need to try to encrypt something to be sure.
	in := []byte("test")
	var outLen int
	if _, err := ossl.EVP_PKEY_encrypt(ctx, nil, &outLen, &in[0], len(in)); err != nil {
		return false
	}
	return true
})

var rsaPKCS1SignatureSupport sync.Map

// SupportsRSAPKCS1v15Signature returns true if the RSA PKCS1 v1.5 padding is supported for signatures with the given hash.
func SupportsRSAPKCS1v15Signature(ch crypto.Hash) (supported bool) {
	v, ok := rsaPKCS1SignatureSupport.Load(ch)
	if ok {
		return v.(bool)
	}
	defer func() {
		rsaPKCS1SignatureSupport.Store(ch, supported)
	}()

	pkey := testRSAPrivateKey()
	ctx, err := ossl.EVP_PKEY_CTX_new(pkey, nil)
	if err != nil {
		return false
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)
	if _, err := ossl.EVP_PKEY_sign_init(ctx); err != nil {
		return false
	}
	if setPKCS1Padding(ctx, ch) != nil {
		return false
	}
	// In FIPS mode, setting the padding might succeed, but the actual signature will fail.
	// So we need to try to sign something to be sure.
	size := 1
	if ch != 0 {
		size = ch.Size()
	}
	in := make([]byte, size, maxHashSize)
	var outLen int
	if _, err := ossl.EVP_PKEY_sign(ctx, nil, &outLen, &in[0], len(in)); err != nil {
		return false
	}
	return true
}

var rsaPSSSupport sync.Map

// SupportsRSAPSS returns true if the RSA PSS padding is supported for signatures with the given hash.
func SupportsRSAPSS(ch crypto.Hash) (supported bool) {
	v, ok := rsaPSSSupport.Load(ch)
	if ok {
		return v.(bool)
	}
	defer func() {
		rsaPSSSupport.Store(ch, supported)
	}()

	if !SupportsHash(ch) {
		// Short-circuit if the hash itself is not supported.
		return false
	}

	pkey := testRSAPrivateKey()
	ctx, err := ossl.EVP_PKEY_CTX_new(pkey, nil)
	if err != nil {
		return false
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)
	if _, err := ossl.EVP_PKEY_sign_init(ctx); err != nil {
		return false
	}
	if setPSSPadding(ctx, 0, ch) != nil {
		return false
	}
	// In FIPS mode, setting the padding might succeed, but the actual signature will fail.
	// So we need to try to sign something to be sure.
	in := make([]byte, ch.Size(), maxHashSize)
	var outLen int
	if _, err := ossl.EVP_PKEY_sign(ctx, nil, &outLen, &in[0], len(in)); err != nil {
		return false
	}
	return true
}

var rsaOAEPSupport sync.Map

type rsaOAEPSupportEntry struct {
	ch      crypto.Hash
	mgfHash crypto.Hash
}

// SupportsRSAOAEP returns true if the RSA OAEP padding is supported for encryption/decryption
// with the given hash and MGF hash.
func SupportsRSAOAEP(h, mgfHash hash.Hash) (supported bool) {
	ch := hashToCryptoHash(h)
	if ch == 0 {
		return false
	}
	mgfCh := hashToCryptoHash(mgfHash)
	if mgfCh == 0 {
		return false
	}
	entry := rsaOAEPSupportEntry{ch, mgfCh}
	v, ok := rsaOAEPSupport.Load(entry)
	if ok {
		return v.(bool)
	}
	defer func() {
		rsaOAEPSupport.Store(entry, supported)
	}()

	if !SupportsHash(ch) {
		// Short-circuit if the hash itself is not supported.
		return false
	}

	pkey := testRSAPrivateKey()
	ctx, err := ossl.EVP_PKEY_CTX_new(pkey, nil)
	if err != nil {
		return false
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)

	if _, err := ossl.EVP_PKEY_encrypt_init(ctx); err != nil {
		return false
	}

	if setOAEPPadding(ctx, h, mgfHash, nil) != nil {
		return false
	}

	// In FIPS mode, setting the padding might succeed, but the actual encryption will fail.
	// So we need to try to encrypt something to be sure.
	in := []byte("test")
	var outLen int
	if _, err := ossl.EVP_PKEY_encrypt(ctx, nil, &outLen, &in[0], len(in)); err != nil {
		return false
	}
	return true
}

// testRSAPrivateKey returns a test RSA private key for use in capability probing functions.
//
// The key is constructed from hard-coded parameters to avoid
// spurious failures due to key generation issues and to avoid the speed cost of
// key generation.
var testRSAPrivateKey = sync.OnceValue(func() ossl.EVP_PKEY_PTR {
	// RSA-2048 key "testRSA2048":
	// https://www.rfc-editor.org/rfc/rfc9500.html#section-2.1
	N := []byte{
		0xB0, 0xF9, 0xE8, 0x19, 0x43, 0xA7, 0xAE, 0x98,
		0x92, 0xAA, 0xDE, 0x17, 0xCA, 0x7C, 0x40, 0xF8,
		0x74, 0x4F, 0xED, 0x2F, 0x81, 0x48, 0xE6, 0xC8,
		0xEA, 0xA2, 0x7B, 0x7D, 0x00, 0x15, 0x48, 0xFB,
		0x51, 0x92, 0xAB, 0x28, 0xB5, 0x6C, 0x50, 0x60,
		0xB1, 0x18, 0xCC, 0xD1, 0x31, 0xE5, 0x94, 0x87,
		0x4C, 0x6C, 0xA9, 0x89, 0xB5, 0x6C, 0x27, 0x29,
		0x6F, 0x09, 0xFB, 0x93, 0xA0, 0x34, 0xDF, 0x32,
		0xE9, 0x7C, 0x6F, 0xF0, 0x99, 0x8C, 0xFD, 0x8E,
		0x6F, 0x42, 0xDD, 0xA5, 0x8A, 0xCD, 0x1F, 0xA9,
		0x79, 0x86, 0xF1, 0x44, 0xF3, 0xD1, 0x54, 0xD6,
		0x76, 0x50, 0x17, 0x5E, 0x68, 0x54, 0xB3, 0xA9,
		0x52, 0x00, 0x3B, 0xC0, 0x68, 0x87, 0xB8, 0x45,
		0x5A, 0xC2, 0xB1, 0x9F, 0x7B, 0x2F, 0x76, 0x50,
		0x4E, 0xBC, 0x98, 0xEC, 0x94, 0x55, 0x71, 0xB0,
		0x78, 0x92, 0x15, 0x0D, 0xDC, 0x6A, 0x74, 0xCA,
		0x0F, 0xBC, 0xD3, 0x54, 0x97, 0xCE, 0x81, 0x53,
		0x4D, 0xAF, 0x94, 0x18, 0x84, 0x4B, 0x13, 0xAE,
		0xA3, 0x1F, 0x9D, 0x5A, 0x6B, 0x95, 0x57, 0xBB,
		0xDF, 0x61, 0x9E, 0xFD, 0x4E, 0x88, 0x7F, 0x2D,
		0x42, 0xB8, 0xDD, 0x8B, 0xC9, 0x87, 0xEA, 0xE1,
		0xBF, 0x89, 0xCA, 0xB8, 0x5E, 0xE2, 0x1E, 0x35,
		0x63, 0x05, 0xDF, 0x6C, 0x07, 0xA8, 0x83, 0x8E,
		0x3E, 0xF4, 0x1C, 0x59, 0x5D, 0xCC, 0xE4, 0x3D,
		0xAF, 0xC4, 0x91, 0x23, 0xEF, 0x4D, 0x8A, 0xBB,
		0xA9, 0x3D, 0x39, 0x05, 0xE4, 0x02, 0x8D, 0x7B,
		0xA9, 0x14, 0x84, 0xA2, 0x75, 0x96, 0xE0, 0x7B,
		0x4B, 0x6E, 0xD9, 0x92, 0xF0, 0x77, 0xB5, 0x24,
		0xD3, 0xDC, 0xFE, 0x7D, 0xDD, 0x55, 0x49, 0xBE,
		0x7C, 0xCE, 0x8D, 0xA0, 0x35, 0xCF, 0xA0, 0xB3,
		0xFB, 0x8F, 0x9E, 0x46, 0xF7, 0x32, 0xB2, 0xA8,
		0x6B, 0x46, 0x01, 0x65, 0xC0, 0x8F, 0x53, 0x13}
	E := []byte{0x01, 0x00, 0x01}
	d := []byte{
		0x41, 0x18, 0x8B, 0x20, 0xCF, 0xDB, 0xDB, 0xC2,
		0xCF, 0x1F, 0xFE, 0x75, 0x2D, 0xCB, 0xAA, 0x72,
		0x39, 0x06, 0x35, 0x2E, 0x26, 0x15, 0xD4, 0x9D,
		0xCE, 0x80, 0x59, 0x7F, 0xCF, 0x0A, 0x05, 0x40,
		0x3B, 0xEF, 0x00, 0xFA, 0x06, 0x51, 0x82, 0xF7,
		0x2D, 0xEC, 0xFB, 0x59, 0x6F, 0x4B, 0x0C, 0xE8,
		0xFF, 0x59, 0x70, 0xBA, 0xF0, 0x7A, 0x89, 0xA5,
		0x19, 0xEC, 0xC8, 0x16, 0xB2, 0xF4, 0xFF, 0xAC,
		0x50, 0x69, 0xAF, 0x1B, 0x06, 0xBF, 0xEF, 0x7B,
		0xF6, 0xBC, 0xD7, 0x9E, 0x4E, 0x81, 0xC8, 0xC5,
		0xA3, 0xA7, 0xD9, 0x13, 0x0D, 0xC3, 0xCF, 0xBA,
		0xDA, 0xE5, 0xF6, 0xD2, 0x88, 0xF9, 0xAE, 0xE3,
		0xF6, 0xFF, 0x92, 0xFA, 0xE0, 0xF8, 0x1A, 0xF5,
		0x97, 0xBE, 0xC9, 0x6A, 0xE9, 0xFA, 0xB9, 0x40,
		0x2C, 0xD5, 0xFE, 0x41, 0xF7, 0x05, 0xBE, 0xBD,
		0xB4, 0x7B, 0xB7, 0x36, 0xD3, 0xFE, 0x6C, 0x5A,
		0x51, 0xE0, 0xE2, 0x07, 0x32, 0xA9, 0x7B, 0x5E,
		0x46, 0xC1, 0xCB, 0xDB, 0x26, 0xD7, 0x48, 0x54,
		0xC6, 0xB6, 0x60, 0x4A, 0xED, 0x46, 0x37, 0x35,
		0xFF, 0x90, 0x76, 0x04, 0x65, 0x57, 0xCA, 0xF9,
		0x49, 0xBF, 0x44, 0x88, 0x95, 0xC2, 0x04, 0x32,
		0xC1, 0xE0, 0x9C, 0x01, 0x4E, 0xA7, 0x56, 0x60,
		0x43, 0x4F, 0x1A, 0x0F, 0x3B, 0xE2, 0x94, 0xBA,
		0xBC, 0x5D, 0x53, 0x0E, 0x6A, 0x10, 0x21, 0x3F,
		0x53, 0xB6, 0x03, 0x75, 0xFC, 0x84, 0xA7, 0x57,
		0x3F, 0x2A, 0xF1, 0x21, 0x55, 0x84, 0xF5, 0xB4,
		0xBD, 0xA6, 0xD4, 0xE8, 0xF9, 0xE1, 0x7A, 0x78,
		0xD9, 0x7E, 0x77, 0xB8, 0x6D, 0xA4, 0xA1, 0x84,
		0x64, 0x75, 0x31, 0x8A, 0x7A, 0x10, 0xA5, 0x61,
		0x01, 0x4E, 0xFF, 0xA2, 0x3A, 0x81, 0xEC, 0x56,
		0xE9, 0xE4, 0x10, 0x9D, 0xEF, 0x8C, 0xB3, 0xF7,
		0x97, 0x22, 0x3F, 0x7D, 0x8D, 0x0D, 0x43, 0x51}
	p := []byte{
		0xDD, 0x10, 0x57, 0x02, 0x38, 0x2F, 0x23, 0x2B,
		0x36, 0x81, 0xF5, 0x37, 0x91, 0xE2, 0x26, 0x17,
		0xC7, 0xBF, 0x4E, 0x9A, 0xCB, 0x81, 0xED, 0x48,
		0xDA, 0xF6, 0xD6, 0x99, 0x5D, 0xA3, 0xEA, 0xB6,
		0x42, 0x83, 0x9A, 0xFF, 0x01, 0x2D, 0x2E, 0xA6,
		0x28, 0xB9, 0x0A, 0xF2, 0x79, 0xFD, 0x3E, 0x6F,
		0x7C, 0x93, 0xCD, 0x80, 0xF0, 0x72, 0xF0, 0x1F,
		0xF2, 0x44, 0x3B, 0x3E, 0xE8, 0xF2, 0x4E, 0xD4,
		0x69, 0xA7, 0x96, 0x13, 0xA4, 0x1B, 0xD2, 0x40,
		0x20, 0xF9, 0x2F, 0xD1, 0x10, 0x59, 0xBD, 0x1D,
		0x0F, 0x30, 0x1B, 0x5B, 0xA7, 0xA9, 0xD3, 0x63,
		0x7C, 0xA8, 0xD6, 0x5C, 0x1A, 0x98, 0x15, 0x41,
		0x7D, 0x8E, 0xAB, 0x73, 0x4B, 0x0B, 0x4F, 0x3A,
		0x2C, 0x66, 0x1D, 0x9A, 0x1A, 0x82, 0xF3, 0xAC,
		0x73, 0x4C, 0x40, 0x53, 0x06, 0x69, 0xAB, 0x8E,
		0x47, 0x30, 0x45, 0xA5, 0x8E, 0x65, 0x53, 0x9D}
	q := []byte{
		0xCC, 0xF1, 0xE5, 0xBB, 0x90, 0xC8, 0xE9, 0x78,
		0x1E, 0xA7, 0x5B, 0xEB, 0xF1, 0x0B, 0xC2, 0x52,
		0xE1, 0x1E, 0xB0, 0x23, 0xA0, 0x26, 0x0F, 0x18,
		0x87, 0x55, 0x2A, 0x56, 0x86, 0x3F, 0x4A, 0x64,
		0x21, 0xE8, 0xC6, 0x00, 0xBF, 0x52, 0x3D, 0x6C,
		0xB1, 0xB0, 0xAD, 0xBD, 0xD6, 0x5B, 0xFE, 0xE4,
		0xA8, 0x8A, 0x03, 0x7E, 0x3D, 0x1A, 0x41, 0x5E,
		0x5B, 0xB9, 0x56, 0x48, 0xDA, 0x5A, 0x0C, 0xA2,
		0x6B, 0x54, 0xF4, 0xA6, 0x39, 0x48, 0x52, 0x2C,
		0x3D, 0x5F, 0x89, 0xB9, 0x4A, 0x72, 0xEF, 0xFF,
		0x95, 0x13, 0x4D, 0x59, 0x40, 0xCE, 0x45, 0x75,
		0x8F, 0x30, 0x89, 0x80, 0x90, 0x89, 0x56, 0x58,
		0x8E, 0xEF, 0x57, 0x5B, 0x3E, 0x4B, 0xC4, 0xC3,
		0x68, 0xCF, 0xE8, 0x13, 0xEE, 0x9C, 0x25, 0x2C,
		0x2B, 0x02, 0xE0, 0xDF, 0x91, 0xF1, 0xAA, 0x01,
		0x93, 0x8D, 0x38, 0x68, 0x5D, 0x60, 0xBA, 0x6F}
	qInv := []byte{
		0x0A, 0x81, 0xD8, 0xA6, 0x18, 0x31, 0x4A, 0x80,
		0x3A, 0xF6, 0x1C, 0x06, 0x71, 0x1F, 0x2C, 0x39,
		0xB2, 0x66, 0xFF, 0x41, 0x4D, 0x53, 0x47, 0x6D,
		0x1D, 0xA5, 0x2A, 0x43, 0x18, 0xAA, 0xFE, 0x4B,
		0x96, 0xF0, 0xDA, 0x07, 0x15, 0x5F, 0x8A, 0x51,
		0x34, 0xDA, 0xB8, 0x8E, 0xE2, 0x9E, 0x81, 0x68,
		0x07, 0x6F, 0xCD, 0x78, 0xCA, 0x79, 0x1A, 0xC6,
		0x34, 0x42, 0xA8, 0x1C, 0xD0, 0x69, 0x39, 0x27,
		0xD8, 0x08, 0xE3, 0x35, 0xE8, 0xD8, 0xCB, 0xF2,
		0x12, 0x19, 0x07, 0x50, 0x9A, 0x57, 0x75, 0x9B,
		0x4F, 0x9A, 0x18, 0xFA, 0x3A, 0x7B, 0x33, 0x37,
		0x79, 0xED, 0xDE, 0x7A, 0x45, 0x93, 0x84, 0xF8,
		0x44, 0x4A, 0xDA, 0xEC, 0xFF, 0xEC, 0x95, 0xFD,
		0x55, 0x2B, 0x0C, 0xFC, 0xB6, 0xC7, 0xF6, 0x92,
		0x62, 0x6D, 0xDE, 0x1E, 0xF2, 0x68, 0xA4, 0x0D,
		0x2F, 0x67, 0xB5, 0xC8, 0xAA, 0x38, 0x7F, 0xF7}
	dP := []byte{
		0x09, 0xED, 0x54, 0xEA, 0xED, 0x98, 0xF8, 0x4C,
		0x55, 0x7B, 0x4A, 0x86, 0xBF, 0x4F, 0x57, 0x84,
		0x93, 0xDC, 0xBC, 0x6B, 0xE9, 0x1D, 0xA1, 0x89,
		0x37, 0x04, 0x04, 0xA9, 0x08, 0x72, 0x76, 0xF4,
		0xCE, 0x51, 0xD8, 0xA1, 0x00, 0xED, 0x85, 0x7D,
		0xC2, 0xB0, 0x64, 0x94, 0x74, 0xF3, 0xF1, 0x5C,
		0xD2, 0x4C, 0x54, 0xDB, 0x28, 0x71, 0x10, 0xE5,
		0x6E, 0x5C, 0xB0, 0x08, 0x68, 0x2F, 0x91, 0x68,
		0xAA, 0x81, 0xF3, 0x14, 0x58, 0xB7, 0x43, 0x1E,
		0xCC, 0x1C, 0x44, 0x90, 0x6F, 0xDA, 0x87, 0xCA,
		0x89, 0x47, 0x10, 0xC3, 0x71, 0xE9, 0x07, 0x6C,
		0x1D, 0x49, 0xFB, 0xAE, 0x51, 0x27, 0x69, 0x34,
		0xF2, 0xAD, 0x78, 0x77, 0x89, 0xF4, 0x2D, 0x0F,
		0xA0, 0xB4, 0xC9, 0x39, 0x85, 0x5D, 0x42, 0x12,
		0x09, 0x6F, 0x70, 0x28, 0x0A, 0x4E, 0xAE, 0x7C,
		0x8A, 0x27, 0xD9, 0xC8, 0xD0, 0x77, 0x2E, 0x65}
	dQ := []byte{
		0x8C, 0xB6, 0x85, 0x7A, 0x7B, 0xD5, 0x46, 0x5F,
		0x80, 0x04, 0x7E, 0x9B, 0x87, 0xBC, 0x00, 0x27,
		0x31, 0x84, 0x05, 0x81, 0xE0, 0x62, 0x61, 0x39,
		0x01, 0x2A, 0x5B, 0x50, 0x5F, 0x0A, 0x33, 0x84,
		0x7E, 0xB7, 0xB8, 0xC3, 0x28, 0x99, 0x49, 0xAD,
		0x48, 0x6F, 0x3B, 0x4B, 0x3D, 0x53, 0x9A, 0xB5,
		0xDA, 0x76, 0x30, 0x21, 0xCB, 0xC8, 0x2C, 0x1B,
		0xA2, 0x34, 0xA5, 0x66, 0x8D, 0xED, 0x08, 0x01,
		0xB8, 0x59, 0xF3, 0x43, 0xF1, 0xCE, 0x93, 0x04,
		0xE6, 0xFA, 0xA2, 0xB0, 0x02, 0xCA, 0xD9, 0xB7,
		0x8C, 0xDE, 0x5C, 0xDC, 0x2C, 0x1F, 0xB4, 0x17,
		0x1C, 0x42, 0x42, 0x16, 0x70, 0xA6, 0xAB, 0x0F,
		0x50, 0xCC, 0x4A, 0x19, 0x4E, 0xB3, 0x6D, 0x1C,
		0x91, 0xE9, 0x35, 0xBA, 0x01, 0xB9, 0x59, 0xD8,
		0x72, 0x8B, 0x9E, 0x64, 0x42, 0x6B, 0x3F, 0xC3,
		0xA7, 0x50, 0x6D, 0xEB, 0x52, 0x39, 0xA8, 0xA7}

	// Convert []byte to BigInt using BN_bin2bn and bnToBig
	bytesToBigInt := func(b []byte) BigInt {
		bn, err := ossl.BN_bin2bn(base(b), int32(len(b)), nil)
		if err != nil {
			panic(err)
		}
		defer ossl.BN_free(bn)
		return bnToBig(bn)
	}

	priv, err := NewPrivateKeyRSA(
		bytesToBigInt(N),
		bytesToBigInt(E),
		bytesToBigInt(d),
		bytesToBigInt(p),
		bytesToBigInt(q),
		bytesToBigInt(dP),
		bytesToBigInt(dQ),
		bytesToBigInt(qInv),
	)
	if err != nil {
		panic("failed to create test RSA private key: " + err.Error())
	}
	// Prevent finalization to avoid freeing OpenSSL objects.
	runtime.SetFinalizer(priv, nil)
	return priv._pkey
})
