//go:build !cmd_go_bootstrap && cgo

package openssl

import (
	"crypto"
	"errors"
	"hash"
	"strconv"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

// cacheMD is a cache of crypto.Hash to GO_EVP_MD_PTR.
var cacheMD sync.Map

// hashFuncHash calls fn() and returns its result.
// If fn() panics, the panic is recovered and returned as an error.
// This is used to avoid aborting the program when calling
// an unsupported hash function. It is the caller's responsibility
// to check the returned value.
func hashFuncHash(fn func() hash.Hash) (h hash.Hash, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		h = nil
		switch e := r.(type) {
		case error:
			err = e
		case string:
			err = errors.New(e)
		default:
			err = errors.New("unsupported panic")
		}
	}()
	return fn(), nil
}

// hashToMD converts a hash.Hash implementation from this package to a GO_EVP_MD_PTR.
func hashToMD(h hash.Hash) ossl.EVP_MD_PTR {
	var ch crypto.Hash
	switch h.(type) {
	case *sha1Hash, *sha1Marshal:
		ch = crypto.SHA1
	case *sha224Hash, *sha224Marshal:
		ch = crypto.SHA224
	case *sha256Hash, *sha256Marshal:
		ch = crypto.SHA256
	case *sha384Hash, *sha384Marshal:
		ch = crypto.SHA384
	case *sha512Hash, *sha512Marshal:
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

// hashFuncToMD converts a hash.Hash function to a GO_EVP_MD_PTR.
// See [hashFuncHash] for details on error handling.
func hashFuncToMD(fn func() hash.Hash) (ossl.EVP_MD_PTR, error) {
	h, err := hashFuncHash(fn)
	if err != nil {
		return nil, err
	}
	md := hashToMD(h)
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}
	return md, nil
}

// cryptoHashToMD converts a crypto.Hash to a GO_EVP_MD_PTR.
func cryptoHashToMD(ch crypto.Hash) (md ossl.EVP_MD_PTR) {
	if v, ok := cacheMD.Load(ch); ok {
		return v.(ossl.EVP_MD_PTR)
	}
	defer func() {
		if md != nil {
			switch vMajor {
			case 1:
				// On OpenSSL 1 EVP_MD objects can be not-nil even
				// when they are not supported. We need to pass the md
				// to a EVP_MD_CTX to really know if they can be used.
				ctx, _ := ossl.EVP_MD_CTX_new()
				if ossl.EVP_DigestInit_ex(ctx, md, nil) != nil {
					md = nil
				}
				ossl.EVP_MD_CTX_free(ctx)
			case 3:
				// On OpenSSL 3, directly operating on a EVP_MD object
				// not created by EVP_MD_fetch has negative performance
				// implications, as digest operations will have
				// to fetch it on every call. Better to just fetch it once here.
				md, _ = ossl.EVP_MD_fetch(nil, ossl.EVP_MD_get0_name(md), nil)
			default:
				panic(errUnsupportedVersion())
			}
		}
		cacheMD.Store(ch, md)
	}()
	// SupportsHash returns false for MD5SHA1 because we don't
	// provide a hash.Hash implementation for it. Yet, it can
	// still be used when signing/verifying with an RSA key.
	if ch == crypto.MD5SHA1 {
		if vMajor == 1 && vMinor == 0 {
			return ossl.EVP_md5_sha1_backport()
		} else {
			return ossl.EVP_md5_sha1()
		}
	}
	switch ch {
	case crypto.MD4:
		return ossl.EVP_md4()
	case crypto.MD5:
		return ossl.EVP_md5()
	case crypto.SHA1:
		return ossl.EVP_sha1()
	case crypto.SHA224:
		return ossl.EVP_sha224()
	case crypto.SHA256:
		return ossl.EVP_sha256()
	case crypto.SHA384:
		return ossl.EVP_sha384()
	case crypto.SHA512:
		return ossl.EVP_sha512()
	case crypto.SHA3_224:
		if versionAtOrAbove(1, 1, 1) {
			return ossl.EVP_sha3_224()
		}
	case crypto.SHA3_256:
		if versionAtOrAbove(1, 1, 1) {
			return ossl.EVP_sha3_256()
		}
	case crypto.SHA3_384:
		if versionAtOrAbove(1, 1, 1) {
			return ossl.EVP_sha3_384()
		}
	case crypto.SHA3_512:
		if versionAtOrAbove(1, 1, 1) {
			return ossl.EVP_sha3_512()
		}
	}
	return nil
}

// generateEVPPKey generates a new EVP_PKEY with the given id and properties.
func generateEVPPKey(id int, bits int, curve string) (ossl.EVP_PKEY_PTR, error) {
	if bits != 0 && curve != "" {
		return nil, fail("incorrect generateEVPPKey parameters")
	}
	var curveID int
	if curve != "" {
		var err error
		curveID, err = curveNID(curve)
		if err != nil {
			return nil, err
		}
	}
	var pkey ossl.EVP_PKEY_PTR
	switch vMajor {
	case 1:
		ctx, err := ossl.EVP_PKEY_CTX_new_id(int32(id), nil)
		if err != nil {
			return nil, err
		}
		defer ossl.EVP_PKEY_CTX_free(ctx)
		if err := ossl.EVP_PKEY_keygen_init(ctx); err != nil {
			return nil, err
		}
		if bits != 0 {
			if err := ossl.EVP_PKEY_CTX_ctrl(ctx, int32(id), -1, ossl.EVP_PKEY_CTRL_RSA_KEYGEN_BITS, int32(bits), nil); err != nil {
				return nil, err
			}
		}
		if curve != "" {
			if err := ossl.EVP_PKEY_CTX_ctrl(ctx, int32(id), -1, ossl.EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, int32(curveID), nil); err != nil {
				return nil, err
			}
		}
		if err := ossl.EVP_PKEY_keygen(ctx, &pkey); err != nil {
			return nil, err
		}
	case 3:
		var err error
		switch id {
		case ossl.EVP_PKEY_RSA:
			pkey, err = ossl.EVP_PKEY_Q_keygen_RSA(nil, nil, cStringData(ossl.KeyTypeRSA), bits)
		case ossl.EVP_PKEY_EC:
			pkey, err = ossl.EVP_PKEY_Q_keygen_EC(nil, nil, cStringData(ossl.KeyTypeEC), ossl.OBJ_nid2sn(int32(curveID)))
		case ossl.EVP_PKEY_ED25519:
			pkey, err = ossl.EVP_PKEY_Q_keygen_ED25519(nil, nil, cStringData(ossl.KeyTypeED25519))
		default:
			panic("unsupported key type '" + strconv.Itoa(int(id)) + "'")
		}
		if err != nil {
			return nil, err
		}
	default:
		panic(errUnsupportedVersion())
	}

	return pkey, nil
}

type withKeyFunc func(func(ossl.EVP_PKEY_PTR) error) error
type initFunc func(ossl.EVP_PKEY_CTX_PTR) error
type cryptFunc func(ossl.EVP_PKEY_CTX_PTR, *byte, *int, *byte, int) error
type verifyFunc func(ossl.EVP_PKEY_CTX_PTR, *byte, int, *byte, int) error

func setupEVP(withKey withKeyFunc, padding int,
	h, mgfHash hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc) (_ ossl.EVP_PKEY_CTX_PTR, err error) {
	var ctx ossl.EVP_PKEY_CTX_PTR
	err = withKey(func(pkey ossl.EVP_PKEY_PTR) (err error) {
		ctx, err = ossl.EVP_PKEY_CTX_new(pkey, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if ctx != nil {
				ossl.EVP_PKEY_CTX_free(ctx)
				ctx = nil
			}
		}
	}()
	if err := init(ctx); err != nil {
		return nil, err
	}
	if padding == 0 {
		return ctx, nil
	}
	// Each padding type has its own requirements in terms of when to apply the padding,
	// so it can't be just set at this point.
	setPadding := func() error {
		if err := ossl.EVP_PKEY_CTX_ctrl(ctx, ossl.EVP_PKEY_RSA, -1, ossl.EVP_PKEY_CTRL_RSA_PADDING, int32(padding), nil); err != nil {
			return err
		}
		return nil
	}
	switch padding {
	case ossl.RSA_PKCS1_OAEP_PADDING:
		md := hashToMD(h)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		var mgfMD ossl.EVP_MD_PTR
		if mgfHash != nil {
			// mgfHash is optional, but if it is set it must match a supported hash function.
			mgfMD = hashToMD(mgfHash)
			if mgfMD == nil {
				return nil, errors.New("crypto/rsa: unsupported hash function")
			}
		}
		// setPadding must happen before setting EVP_PKEY_CTRL_RSA_OAEP_MD.
		if err := setPadding(); err != nil {
			return nil, err
		}
		if err := ossl.EVP_PKEY_CTX_ctrl(ctx, ossl.EVP_PKEY_RSA, -1, ossl.EVP_PKEY_CTRL_RSA_OAEP_MD, 0, unsafe.Pointer(md)); err != nil {
			return nil, err
		}
		if mgfHash != nil {
			if err := ossl.EVP_PKEY_CTX_ctrl(ctx, ossl.EVP_PKEY_RSA, -1, ossl.EVP_PKEY_CTRL_RSA_MGF1_MD, 0, unsafe.Pointer(mgfMD)); err != nil {
				return nil, err
			}
		}
		// ctx takes ownership of label, so malloc a copy for OpenSSL to free.
		// OpenSSL does not take ownership of the label if the length is zero,
		// so better avoid the allocation.
		if len(label) > 0 {
			clabel := cryptoMalloc(len(label))
			copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
			var err error
			if vMajor == 3 {
				err = ossl.EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, clabel, int32(len(label)))
			} else {
				err = ossl.EVP_PKEY_CTX_ctrl(ctx, ossl.EVP_PKEY_RSA, -1, ossl.EVP_PKEY_CTRL_RSA_OAEP_LABEL, int32(len(label)), clabel)
			}
			if err != nil {
				cryptoFree(clabel)
				return nil, err
			}
		}
	case ossl.RSA_PKCS1_PSS_PADDING:
		md := cryptoHashToMD(ch)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if err := ossl.EVP_PKEY_CTX_ctrl(ctx, ossl.EVP_PKEY_RSA, -1, ossl.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)); err != nil {
			return nil, err
		}
		// setPadding must happen after setting EVP_PKEY_CTRL_MD.
		if err := setPadding(); err != nil {
			return nil, err
		}
		if saltLen != 0 {
			if err := ossl.EVP_PKEY_CTX_ctrl(ctx, ossl.EVP_PKEY_RSA, -1, ossl.EVP_PKEY_CTRL_RSA_PSS_SALTLEN, int32(saltLen), nil); err != nil {
				return nil, err
			}
		}

	case ossl.RSA_PKCS1_PADDING:
		if ch != 0 {
			// We support unhashed messages.
			md := cryptoHashToMD(ch)
			if md == nil {
				return nil, errors.New("crypto/rsa: unsupported hash function")
			}
			if err := ossl.EVP_PKEY_CTX_ctrl(ctx, -1, -1, ossl.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(md)); err != nil {
				return nil, err
			}
			if err := setPadding(); err != nil {
				return nil, err
			}
		}
	default:
		if err := setPadding(); err != nil {
			return nil, err
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
	defer ossl.EVP_PKEY_CTX_free(ctx)
	var pkeySize int
	withKey(func(pkey ossl.EVP_PKEY_PTR) error {
		pkeySize = int(ossl.EVP_PKEY_get_size(pkey))
		return nil
	})
	outLen := pkeySize
	out := make([]byte, pkeySize)
	if err := crypt(ctx, base(out), &outLen, base(in), len(in)); err != nil {
		return nil, err
	}
	// The size returned by EVP_PKEY_get_size() is only preliminary and not exact,
	// so the final contents of the out buffer may be smaller.
	return out[:outLen], nil
}

func verifyEVP(withKey withKeyFunc, padding int,
	h hash.Hash, label []byte, saltLen int, ch crypto.Hash,
	init initFunc, verify verifyFunc,
	sig, in []byte) error {

	ctx, err := setupEVP(withKey, padding, h, nil, label, saltLen, ch, init)
	if err != nil {
		return err
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)
	return verify(ctx, base(sig), len(sig), base(in), len(in))
}

func evpEncrypt(withKey withKeyFunc, padding int, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, ossl.EVP_PKEY_encrypt_init, ossl.EVP_PKEY_encrypt, msg)
}

func evpDecrypt(withKey withKeyFunc, padding int, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, ossl.EVP_PKEY_decrypt_init, ossl.EVP_PKEY_decrypt, msg)
}

func evpSign(withKey withKeyFunc, padding int, saltLen int, h crypto.Hash, hashed []byte) ([]byte, error) {
	return cryptEVP(withKey, padding, nil, nil, nil, saltLen, h, ossl.EVP_PKEY_sign_init, ossl.EVP_PKEY_sign, hashed)
}

func evpVerify(withKey withKeyFunc, padding int, saltLen int, h crypto.Hash, sig, hashed []byte) error {
	return verifyEVP(withKey, padding, nil, nil, saltLen, h, ossl.EVP_PKEY_verify_init, ossl.EVP_PKEY_verify, sig, hashed)
}

func evpHashSign(withKey withKeyFunc, h crypto.Hash, msg []byte) ([]byte, error) {
	md := cryptoHashToMD(h)
	if md == nil {
		return nil, errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	var out []byte
	var outLen int
	ctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_MD_CTX_free(ctx)
	if err := withKey(func(key ossl.EVP_PKEY_PTR) error {
		return ossl.EVP_DigestSignInit(ctx, nil, md, nil, key)
	}); err != nil {
		return nil, err
	}
	if err := ossl.EVP_DigestUpdate(ctx, unsafe.Pointer(base(msg)), len(msg)); err != nil {
		return nil, err
	}
	// Obtain the signature length
	if err := ossl.EVP_DigestSignFinal(ctx, nil, &outLen); err != nil {
		return nil, err
	}
	out = make([]byte, outLen)
	// Obtain the signature
	if err := ossl.EVP_DigestSignFinal(ctx, base(out), &outLen); err != nil {
		return nil, err
	}
	return out[:outLen], nil
}

func evpHashVerify(withKey withKeyFunc, h crypto.Hash, msg, sig []byte) error {
	md := cryptoHashToMD(h)
	if md == nil {
		return errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	ctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		return err
	}
	defer ossl.EVP_MD_CTX_free(ctx)
	if err := withKey(func(key ossl.EVP_PKEY_PTR) error {
		return ossl.EVP_DigestVerifyInit(ctx, nil, md, nil, key)
	}); err != nil {
		return err
	}
	if err := ossl.EVP_DigestUpdate(ctx, unsafe.Pointer(base(msg)), len(msg)); err != nil {
		return err
	}
	return ossl.EVP_DigestVerifyFinal(ctx, base(sig), len(sig))
}

func newEVPPKEY(key ossl.EC_KEY_PTR) (ossl.EVP_PKEY_PTR, error) {
	pkey, err := ossl.EVP_PKEY_new()
	if err != nil {
		return nil, err
	}
	if err := ossl.EVP_PKEY_assign(pkey, ossl.EVP_PKEY_EC, unsafe.Pointer(key)); err != nil {
		ossl.EVP_PKEY_free(pkey)
		return nil, err
	}
	return pkey, nil
}

// getECKey returns the EC_KEY from pkey.
// If pkey does not contain an EC_KEY it panics.
// The returned key should not be freed.
func getECKey(pkey ossl.EVP_PKEY_PTR) (key ossl.EC_KEY_PTR) {
	if vMajor == 1 && vMinor == 0 {
		if key0, err := ossl.EVP_PKEY_get0(pkey); err == nil {
			key = ossl.EC_KEY_PTR(key0)
		}
	} else {
		key, _ = ossl.EVP_PKEY_get0_EC_KEY(pkey)
	}
	if key == nil {
		panic("pkey does not contain an EC_KEY")
	}
	return key
}

func newEvpFromParams(id int, selection int, params ossl.OSSL_PARAM_PTR) (ossl.EVP_PKEY_PTR, error) {
	ctx, err := ossl.EVP_PKEY_CTX_new_id(int32(id), nil)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)
	if err := ossl.EVP_PKEY_fromdata_init(ctx); err != nil {
		return nil, err
	}
	var pkey ossl.EVP_PKEY_PTR
	if err := ossl.EVP_PKEY_fromdata(ctx, &pkey, int32(selection), params); err != nil {
		return nil, err
	}
	return pkey, nil
}
