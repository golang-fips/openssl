//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"strconv"
	"sync"
	"unsafe"
)

// cacheMD is a cache of crypto.Hash to GO_EVP_MD_PTR.
var cacheMD sync.Map

// hashToMD converts a hash.Hash implementation from this package to a GO_EVP_MD_PTR.
func hashToMD(h hash.Hash) C.GO_EVP_MD_PTR {
	var ch crypto.Hash
	switch h.(type) {
	case *sha1Hash:
		ch = crypto.SHA1
	case *sha224Hash:
		ch = crypto.SHA224
	case *sha256Hash:
		ch = crypto.SHA256
	case *sha384Hash:
		ch = crypto.SHA384
	case *sha512Hash:
		ch = crypto.SHA512
	case *sha3_224Hash:
		ch = crypto.SHA3_224
	case *sha3_256Hash:
		ch = crypto.SHA3_256
	case *sha3_384Hash:
		ch = crypto.SHA3_384
	case *sha3_512Hash:
		ch = crypto.SHA3_512
	}
	if ch != 0 {
		return cryptoHashToMD(ch)
	}
	return nil
}

// cryptoHashToMD converts a crypto.Hash to a GO_EVP_MD_PTR.
func cryptoHashToMD(ch crypto.Hash) (md C.GO_EVP_MD_PTR) {
	if v, ok := cacheMD.Load(ch); ok {
		return v.(C.GO_EVP_MD_PTR)
	}
	defer func() {
		if md != nil && vMajor == 3 {
			// On OpenSSL 3, directly operating on a EVP_MD object
			// not created by EVP_MD_fetch has negative performance
			// implications, as digest operations will have
			// to fetch it on every call. Better to just fetch it once here.
			md = C.go_openssl_EVP_MD_fetch(nil, C.go_openssl_EVP_MD_get0_name(md), nil)
		}
		cacheMD.Store(ch, md)
	}()
	// SupportsHash returns false for MD5SHA1 because we don't
	// provide a hash.Hash implementation for it. Yet, it can
	// still be used when signing/verifying with an RSA key.
	if ch == crypto.MD5SHA1 {
		if vMajor == 1 && vMinor == 0 {
			return C.go_openssl_EVP_md5_sha1_backport()
		} else {
			return C.go_openssl_EVP_md5_sha1()
		}
	}
	switch ch {
	case crypto.MD4:
		return C.go_openssl_EVP_md4()
	case crypto.MD5:
		return C.go_openssl_EVP_md5()
	case crypto.SHA1:
		return C.go_openssl_EVP_sha1()
	case crypto.SHA224:
		return C.go_openssl_EVP_sha224()
	case crypto.SHA256:
		return C.go_openssl_EVP_sha256()
	case crypto.SHA384:
		return C.go_openssl_EVP_sha384()
	case crypto.SHA512:
		return C.go_openssl_EVP_sha512()
	case crypto.SHA3_224:
		if version1_1_1_or_above() {
			return C.go_openssl_EVP_sha3_224()
		}
	case crypto.SHA3_256:
		if version1_1_1_or_above() {
			return C.go_openssl_EVP_sha3_256()
		}
	case crypto.SHA3_384:
		if version1_1_1_or_above() {
			return C.go_openssl_EVP_sha3_384()
		}
	case crypto.SHA3_512:
		if version1_1_1_or_above() {
			return C.go_openssl_EVP_sha3_512()
		}
	}
	return nil
}

func generateEVPPKey(id int, bits int, curve string) (C.GO_EVP_PKEY_PTR, error) {
	if (bits == 0 && curve == "") || (bits != 0 && curve != "") {
		return nil, fail("incorrect generateEVPPKey parameters")
	}
	ctx, err := newEvpPkeyCtxFromID(id)
	if err != nil {
		return nil, err
	}
	defer ctx.free()
	if err := ctx.keygenInit(); err != nil {
		return nil, err
	}
	if bits != 0 {
		if err := ctx.ctrl(id, -1, C.GO_EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, nil); err != nil {
			return nil, err
		}
	}
	if curve != "" {
		nid, err := curveNID(curve)
		if err != nil {
			return nil, err
		}
		if err := ctx.ctrl(id, -1, C.GO_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, int(nid), nil); err != nil {
			return nil, err
		}
	}
	return ctx.keygen()
}

type withKeyFunc func(func(C.GO_EVP_PKEY_PTR) error) error
type initFunc func(evpPkeyCtx) error
type cryptFunc func(ctx evpPkeyCtx, out []byte, in []byte) ([]byte, error)
type verifyFunc func(ctx evpPkeyCtx, out []byte, in []byte) error

var errRSAHashUnsupported = errors.New("crypto/rsa: unsupported hash function")

func setupEVP(withKey withKeyFunc, padding int,
	h, mgfHash hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc) (ctx evpPkeyCtx, err error) {
	defer func() {
		if err != nil {
			ctx.free()
		}
	}()

	err = withKey(func(pkey C.GO_EVP_PKEY_PTR) error {
		ctx, err = newEvpPkeyCtx(pkey)
		return err
	})
	if err != nil {
		return
	}
	if err = init(ctx); err != nil {
		return
	}
	if padding == 0 {
		return ctx, nil
	}
	// Each padding type has its own requirements in terms of when to apply the padding,
	// so it can't be just set at this point.
	setPadding := func() error {
		return ctx.ctrl(C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_PADDING, padding, nil)
	}
	switch padding {
	case C.GO_RSA_PKCS1_OAEP_PADDING:
		md := hashToMD(h)
		if md == nil {
			err = errRSAHashUnsupported
			return
		}
		var mgfMD C.GO_EVP_MD_PTR
		if mgfHash != nil {
			// mgfHash is optional, but if it is set it must match a supported hash function.
			mgfMD = hashToMD(mgfHash)
			if mgfMD == nil {
				err = errRSAHashUnsupported
				return
			}
		}
		// setPadding must happen before setting EVP_PKEY_CTRL_RSA_OAEP_MD.
		if err = setPadding(); err != nil {
			return
		}
		if err = ctx.ctrl(C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_OAEP_MD, 0, unsafe.Pointer(md)); err != nil {
			return
		}
		if mgfHash != nil {
			if err = ctx.ctrl(C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_MGF1_MD, 0, unsafe.Pointer(mgfMD)); err != nil {
				return
			}
		}
		if err = ctx.setRSAOAEPLabel(label); err != nil {
			return
		}
	case C.GO_RSA_PKCS1_PSS_PADDING:
		md := cryptoHashToMD(ch)
		if md == nil {
			err = errRSAHashUnsupported
			return
		}
		if err = ctx.ctrl(C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)); err != nil {
			return
		}
		// setPadding must happen after setting EVP_PKEY_CTRL_MD.
		if err = setPadding(); err != nil {
			return
		}
		if saltLen != 0 {
			if err = ctx.ctrl(C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltLen, nil); err != nil {
				return
			}
		}

	case C.GO_RSA_PKCS1_PADDING:
		if ch != 0 {
			// We support unhashed messages.
			md := cryptoHashToMD(ch)
			if md == nil {
				err = errRSAHashUnsupported
				return
			}
			if err = ctx.ctrl(-1, -1, C.GO_EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)); err != nil {
				return
			}
			if err = setPadding(); err != nil {
				return
			}
		}
	default:
		if err = setPadding(); err != nil {
			return
		}
	}
	return ctx, nil
}

func cryptEVP(withKey withKeyFunc, padding int,
	h, mgfHash hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc, crypt cryptFunc, in []byte) ([]byte, error) {

	ctx, err := setupEVP(withKey, padding, h, mgfHash, label, saltLen, ch, init)
	if err != nil {
		return nil, err
	}
	defer ctx.free()
	var pkeySize C.int
	withKey(func(pkey C.GO_EVP_PKEY_PTR) error {
		pkeySize = C.go_openssl_EVP_PKEY_get_size(pkey)
		return nil
	})
	out := make([]byte, pkeySize)
	return crypt(ctx, out, in)
}

func verifyEVP(withKey withKeyFunc, padding int,
	h hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc, verify verifyFunc,
	sig, in []byte) error {

	ctx, err := setupEVP(withKey, padding, h, nil, label, saltLen, ch, init)
	if err != nil {
		return err
	}
	defer ctx.free()
	return verify(ctx, sig, in)
}

func evpEncrypt(withKey withKeyFunc, padding int, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	encryptInit := func(ctx evpPkeyCtx) error {
		return ctx.encryptInit()
	}
	encrypt := func(ctx evpPkeyCtx, out, in []byte) ([]byte, error) {
		return ctx.encrypt(out, in)
	}
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, encryptInit, encrypt, msg)
}

func evpDecrypt(withKey withKeyFunc, padding int, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	decryptInit := func(ctx evpPkeyCtx) error {
		return ctx.decryptInit()
	}
	decrypt := func(ctx evpPkeyCtx, out, in []byte) ([]byte, error) {
		return ctx.decrypt(out, in)
	}
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, decryptInit, decrypt, msg)
}

func evpSign(withKey withKeyFunc, padding int, saltLen int, h crypto.Hash, hashed []byte) ([]byte, error) {
	signtInit := func(ctx evpPkeyCtx) error {
		return ctx.signInit()
	}
	sign := func(ctx evpPkeyCtx, out, in []byte) ([]byte, error) {
		return ctx.sign(out, in)
	}
	return cryptEVP(withKey, padding, nil, nil, nil, saltLen, h, signtInit, sign, hashed)
}

func evpVerify(withKey withKeyFunc, padding int, saltLen int, h crypto.Hash, sig, hashed []byte) error {
	verifyInit := func(ctx evpPkeyCtx) error {
		return ctx.verifyInit()
	}
	verify := func(ctx evpPkeyCtx, sig, hashed []byte) error {
		return ctx.verify(sig, hashed)
	}
	return verifyEVP(withKey, padding, nil, nil, saltLen, h, verifyInit, verify, sig, hashed)
}

func evpHashSign(withKey withKeyFunc, h crypto.Hash, msg []byte) ([]byte, error) {
	md := cryptoHashToMD(h)
	if md == nil {
		return nil, errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	var out []byte
	var outLen C.size_t
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return nil, newOpenSSLError("EVP_MD_CTX_new failed")
	}
	defer C.go_openssl_EVP_MD_CTX_free(ctx)
	if err := withKey(func(key C.GO_EVP_PKEY_PTR) error {
		if C.go_openssl_EVP_DigestSignInit(ctx, nil, md, nil, key) != 1 {
			return newOpenSSLError("EVP_DigestSignInit failed")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if C.go_openssl_EVP_DigestUpdate(ctx, unsafe.Pointer(base(msg)), C.size_t(len(msg))) != 1 {
		return nil, newOpenSSLError("EVP_DigestUpdate failed")
	}
	// Obtain the signature length
	if C.go_openssl_EVP_DigestSignFinal(ctx, nil, &outLen) != 1 {
		return nil, newOpenSSLError("EVP_DigestSignFinal failed")
	}
	out = make([]byte, outLen)
	// Obtain the signature
	if C.go_openssl_EVP_DigestSignFinal(ctx, base(out), &outLen) != 1 {
		return nil, newOpenSSLError("EVP_DigestSignFinal failed")
	}
	return out[:outLen], nil
}

func evpHashVerify(withKey withKeyFunc, h crypto.Hash, msg, sig []byte) error {
	md := cryptoHashToMD(h)
	if md == nil {
		return errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return newOpenSSLError("EVP_MD_CTX_new failed")
	}
	defer C.go_openssl_EVP_MD_CTX_free(ctx)
	if err := withKey(func(key C.GO_EVP_PKEY_PTR) error {
		if C.go_openssl_EVP_DigestVerifyInit(ctx, nil, md, nil, key) != 1 {
			return newOpenSSLError("EVP_DigestVerifyInit failed")
		}
		return nil
	}); err != nil {
		return err
	}
	if C.go_openssl_EVP_DigestUpdate(ctx, unsafe.Pointer(base(msg)), C.size_t(len(msg))) != 1 {
		return newOpenSSLError("EVP_DigestUpdate failed")
	}
	if C.go_openssl_EVP_DigestVerifyFinal(ctx, base(sig), C.size_t(len(sig))) != 1 {
		return newOpenSSLError("EVP_DigestVerifyFinal failed")
	}
	return nil
}

func newEVPPKEY(key C.GO_EC_KEY_PTR) (C.GO_EVP_PKEY_PTR, error) {
	pkey := C.go_openssl_EVP_PKEY_new()
	if pkey == nil {
		return nil, newOpenSSLError("EVP_PKEY_new failed")
	}
	if C.go_openssl_EVP_PKEY_assign(pkey, C.GO_EVP_PKEY_EC, unsafe.Pointer(key)) != 1 {
		C.go_openssl_EVP_PKEY_free(pkey)
		return nil, newOpenSSLError("EVP_PKEY_assign failed")
	}
	return pkey, nil
}

// getECKey returns the EC_KEY from pkey.
// If pkey does not contain an EC_KEY it panics.
// The returned key should not be freed.
func getECKey(pkey C.GO_EVP_PKEY_PTR) (key C.GO_EC_KEY_PTR) {
	if vMajor == 1 && vMinor == 0 {
		if key0 := C.go_openssl_EVP_PKEY_get0(pkey); key0 != nil {
			key = C.GO_EC_KEY_PTR(key0)
		}
	} else {
		key = C.go_openssl_EVP_PKEY_get0_EC_KEY(pkey)
	}
	if key == nil {
		panic("pkey does not contain an EC_KEY")
	}
	return key
}

func newEvpFromParams(id int, selection int, params C.GO_OSSL_PARAM_PTR) (C.GO_EVP_PKEY_PTR, error) {
	ctx, err := newEvpPkeyCtxFromID(id)
	if err != nil {
		return nil, err
	}
	defer ctx.free()
	if err := ctx.fromdataInit(); err != nil {
		return nil, err
	}
	return ctx.fromdata(selection, params)
}
