//go:build !cmd_go_bootstrap

package openssl

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
func hashToMD(h hash.Hash) _EVP_MD_PTR {
	if h, ok := h.(*evpHash); ok {
		return h.alg.md
	}
	return nil
}

// hashFuncToMD converts a hash.Hash function to a GO_EVP_MD_PTR.
// See [hashFuncHash] for details on error handling.
func hashFuncToMD(fn func() hash.Hash) (_EVP_MD_PTR, error) {
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

type hashAlgorithm struct {
	md             _EVP_MD_PTR
	ch             crypto.Hash
	size           int
	blockSize      int
	marshallable   bool
	magic          string
	marshalledSize int
}

// loadHash converts a crypto.Hash to a EVP_MD.
func loadHash(ch crypto.Hash) *hashAlgorithm {
	if v, ok := cacheMD.Load(ch); ok {
		return v.(*hashAlgorithm)
	}

	var hash hashAlgorithm
	switch ch {
	case crypto.RIPEMD160:
		hash.md = go_openssl_EVP_ripemd160()
	case crypto.MD4:
		hash.md = go_openssl_EVP_md4()
	case crypto.MD5:
		hash.md = go_openssl_EVP_md5()
		hash.magic = md5Magic
		hash.marshalledSize = md5MarshaledSize
	case crypto.MD5SHA1:
		hash.md = go_openssl_EVP_md5_sha1()
	case crypto.SHA1:
		hash.md = go_openssl_EVP_sha1()
		hash.magic = sha1Magic
		hash.marshalledSize = sha1MarshaledSize
	case crypto.SHA224:
		hash.md = go_openssl_EVP_sha224()
		hash.magic = magic224
		hash.marshalledSize = marshaledSize256
	case crypto.SHA256:
		hash.md = go_openssl_EVP_sha256()
		hash.magic = magic256
		hash.marshalledSize = marshaledSize256
	case crypto.SHA384:
		hash.md = go_openssl_EVP_sha384()
		hash.magic = magic384
		hash.marshalledSize = marshaledSize512
	case crypto.SHA512:
		hash.md = go_openssl_EVP_sha512()
		hash.magic = magic512
		hash.marshalledSize = marshaledSize512
	case crypto.SHA512_224:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = go_openssl_EVP_sha512_224()
			hash.magic = magic512_224
			hash.marshalledSize = marshaledSize512
		}
	case crypto.SHA512_256:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = go_openssl_EVP_sha512_256()
			hash.magic = magic512_256
			hash.marshalledSize = marshaledSize512
		}
	case crypto.SHA3_224:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = go_openssl_EVP_sha3_224()
		}
	case crypto.SHA3_256:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = go_openssl_EVP_sha3_256()
		}
	case crypto.SHA3_384:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = go_openssl_EVP_sha3_384()
		}
	case crypto.SHA3_512:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = go_openssl_EVP_sha3_512()
		}
	}
	if hash.md == nil {
		cacheMD.Store(ch, (*hashAlgorithm)(nil))
		return nil
	}
	hash.ch = ch
	hash.size = int(go_openssl_EVP_MD_get_size(hash.md))
	hash.blockSize = int(go_openssl_EVP_MD_get_block_size(hash.md))
	if vMajor == 3 {
		// On OpenSSL 3, directly operating on a EVP_MD object
		// not created by EVP_MD_fetch has negative performance
		// implications, as digest operations will have
		// to fetch it on every call. Better to just fetch it once here.
		md, _ := go_openssl_EVP_MD_fetch(nil, go_openssl_EVP_MD_get0_name(hash.md), nil)
		// Don't overwrite md in case it can't be fetched, as the md may still be used
		// outside of EVP_MD_CTX, for example to sign and verify RSA signatures.
		if md != nil {
			hash.md = md
		}
	}
	hash.marshallable = hash.magic != "" && isHashMarshallable(hash.md)
	cacheMD.Store(ch, &hash)
	return &hash
}

// generateEVPPKey generates a new EVP_PKEY with the given id and properties.
func generateEVPPKey(id, bits int32, curve string) (_EVP_PKEY_PTR, error) {
	if bits != 0 && curve != "" {
		return nil, fail("incorrect generateEVPPKey parameters")
	}
	var pkey _EVP_PKEY_PTR
	switch vMajor {
	case 1:
		ctx, err := go_openssl_EVP_PKEY_CTX_new_id(id, nil)
		if err != nil {
			return nil, err
		}
		defer go_openssl_EVP_PKEY_CTX_free(ctx)
		if _, err := go_openssl_EVP_PKEY_keygen_init(ctx); err != nil {
			return nil, err
		}
		if bits != 0 {
			if _, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, id, -1, _EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, nil); err != nil {
				return nil, err
			}
		}
		if curve != "" {
			if _, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, id, -1, _EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, curveNID(curve), nil); err != nil {
				return nil, err
			}
		}
		if _, err := go_openssl_EVP_PKEY_keygen(ctx, &pkey); err != nil {
			return nil, err
		}
	case 3:
		var err error
		switch id {
		case _EVP_PKEY_RSA:
			pkey, err = go_openssl_EVP_PKEY_Q_keygen_RSA(nil, nil, _KeyTypeRSA.ptr(), int(bits))
		case _EVP_PKEY_EC:
			pkey, err = go_openssl_EVP_PKEY_Q_keygen_EC(nil, nil, _KeyTypeEC.ptr(), go_openssl_OBJ_nid2sn(curveNID(curve)))
		case _EVP_PKEY_ED25519:
			pkey, err = go_openssl_EVP_PKEY_Q_keygen_ED25519(nil, nil, _KeyTypeED25519.ptr())
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

type withKeyFunc func(func(_EVP_PKEY_PTR) error) error
type initFunc func(_EVP_PKEY_CTX_PTR) error
type cryptFunc func(_EVP_PKEY_CTX_PTR, *byte, *int, *byte, int) error
type verifyFunc func(_EVP_PKEY_CTX_PTR, *byte, int, *byte, int) error

func setupEVP(withKey withKeyFunc, padding int32,
	h, mgfHash hash.Hash, label []byte, saltLen int32, ch crypto.Hash,
	init initFunc) (_ _EVP_PKEY_CTX_PTR, err error) {
	var ctx _EVP_PKEY_CTX_PTR
	if err := withKey(func(pkey _EVP_PKEY_PTR) error {
		ctx, err = go_openssl_EVP_PKEY_CTX_new(pkey, nil)
		return err
	}); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if ctx != nil {
				go_openssl_EVP_PKEY_CTX_free(ctx)
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
		_, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, _EVP_PKEY_RSA, -1, _EVP_PKEY_CTRL_RSA_PADDING, padding, nil)
		return err
	}
	switch padding {
	case _RSA_PKCS1_OAEP_PADDING:
		md := hashToMD(h)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		var mgfMD _EVP_MD_PTR
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
		if _, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, _EVP_PKEY_RSA, -1, _EVP_PKEY_CTRL_RSA_OAEP_MD, 0, unsafe.Pointer(md)); err != nil {
			return nil, err
		}
		if mgfHash != nil {
			if _, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, _EVP_PKEY_RSA, -1, _EVP_PKEY_CTRL_RSA_MGF1_MD, 0, unsafe.Pointer(mgfMD)); err != nil {
				return nil, err
			}
		}
		// ctx takes ownership of label, so malloc a copy for OpenSSL to free.
		// OpenSSL does not take ownership of the label if the length is zero,
		// so better avoid the allocation.
		var clabel *byte
		if len(label) > 0 {
			clabel = (*byte)(cryptoMalloc(len(label)))
			copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
			var err error
			if vMajor == 3 {
				_, err = go_openssl_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, unsafe.Pointer(clabel), int32(len(label)))
			} else {
				_, err = go_openssl_EVP_PKEY_CTX_ctrl(ctx, _EVP_PKEY_RSA, -1, _EVP_PKEY_CTRL_RSA_OAEP_LABEL, int32(len(label)), unsafe.Pointer(clabel))
			}
			if err != nil {
				cryptoFree(unsafe.Pointer(clabel))
				return nil, err
			}
		}
	case _RSA_PKCS1_PSS_PADDING:
		alg := loadHash(ch)
		if alg == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if _, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, _EVP_PKEY_RSA, -1, _EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(alg.md)); err != nil {
			return nil, err
		}
		// setPadding must happen after setting EVP_PKEY_CTRL_MD.
		if err := setPadding(); err != nil {
			return nil, err
		}
		if saltLen != 0 {
			if _, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, _EVP_PKEY_RSA, -1, _EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltLen, nil); err != nil {
				return nil, err
			}
		}

	case _RSA_PKCS1_PADDING:
		if ch != 0 {
			// We support unhashed messages.
			alg := loadHash(ch)
			if alg == nil {
				return nil, errors.New("crypto/rsa: unsupported hash function")
			}
			if _, err := go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, -1, _EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(alg.md)); err != nil {
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

func cryptEVP(withKey withKeyFunc, padding int32,
	h, mgfHash hash.Hash, label []byte, saltLen int32, ch crypto.Hash,
	init initFunc, crypt cryptFunc, in []byte) ([]byte, error) {

	ctx, err := setupEVP(withKey, padding, h, mgfHash, label, saltLen, ch, init)
	if err != nil {
		return nil, err
	}
	defer go_openssl_EVP_PKEY_CTX_free(ctx)
	var pkeySize int32
	if err := withKey(func(pkey _EVP_PKEY_PTR) (err error) {
		pkeySize, err = go_openssl_EVP_PKEY_get_size(pkey)
		return err
	}); err != nil {
		return nil, err
	}
	outLen := int(pkeySize)
	out := make([]byte, pkeySize)
	if err := crypt(ctx, base(out), &outLen, base(in), len(in)); err != nil {
		return nil, err
	}
	// The size returned by EVP_PKEY_get_size() is only preliminary and not exact,
	// so the final contents of the out buffer may be smaller.
	return out[:outLen], nil
}

func verifyEVP(withKey withKeyFunc, padding int32,
	h hash.Hash, label []byte, saltLen int32, ch crypto.Hash,
	init initFunc, verify verifyFunc,
	sig, in []byte) error {

	ctx, err := setupEVP(withKey, padding, h, nil, label, saltLen, ch, init)
	if err != nil {
		return err
	}
	defer go_openssl_EVP_PKEY_CTX_free(ctx)
	return verify(ctx, base(sig), len(sig), base(in), len(in))
}

func evpEncrypt(withKey withKeyFunc, padding int32, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	encryptInit := func(ctx _EVP_PKEY_CTX_PTR) error {
		_, err := go_openssl_EVP_PKEY_encrypt_init(ctx)
		return err
	}
	encrypt := func(ctx _EVP_PKEY_CTX_PTR, out *byte, outLen *int, in *byte, inLen int) error {
		if _, err := go_openssl_EVP_PKEY_encrypt(ctx, out, outLen, in, inLen); err != nil {
			return err
		}
		return nil
	}
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, encryptInit, encrypt, msg)
}

func evpDecrypt(withKey withKeyFunc, padding int32, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	decryptInit := func(ctx _EVP_PKEY_CTX_PTR) error {
		_, err := go_openssl_EVP_PKEY_decrypt_init(ctx)
		return err
	}
	decrypt := func(ctx _EVP_PKEY_CTX_PTR, out *byte, outLen *int, in *byte, inLen int) error {
		_, err := go_openssl_EVP_PKEY_decrypt(ctx, out, outLen, in, inLen)
		return err
	}
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, decryptInit, decrypt, msg)
}

func evpSign(withKey withKeyFunc, padding int32, saltLen int32, h crypto.Hash, hashed []byte) ([]byte, error) {
	signtInit := func(ctx _EVP_PKEY_CTX_PTR) error {
		_, err := go_openssl_EVP_PKEY_sign_init(ctx)
		return err
	}
	sign := func(ctx _EVP_PKEY_CTX_PTR, out *byte, outLen *int, in *byte, inLen int) error {
		_, err := go_openssl_EVP_PKEY_sign(ctx, out, outLen, in, inLen)
		return err
	}
	return cryptEVP(withKey, padding, nil, nil, nil, saltLen, h, signtInit, sign, hashed)
}

func evpVerify(withKey withKeyFunc, padding int32, saltLen int32, h crypto.Hash, sig, hashed []byte) error {
	verifyInit := func(ctx _EVP_PKEY_CTX_PTR) error {
		_, err := go_openssl_EVP_PKEY_verify_init(ctx)
		return err
	}
	verify := func(ctx _EVP_PKEY_CTX_PTR, out *byte, outLen int, in *byte, inLen int) error {
		_, err := go_openssl_EVP_PKEY_verify(ctx, out, outLen, in, inLen)
		return err
	}
	return verifyEVP(withKey, padding, nil, nil, saltLen, h, verifyInit, verify, sig, hashed)
}

func evpHashSign(withKey withKeyFunc, h crypto.Hash, msg []byte) ([]byte, error) {
	alg := loadHash(h)
	if alg == nil {
		return nil, errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	var out []byte
	var outLen int
	ctx, err := go_openssl_EVP_MD_CTX_new()
	if err != nil {
		return nil, err
	}
	defer go_openssl_EVP_MD_CTX_free(ctx)
	if err := withKey(func(key _EVP_PKEY_PTR) error {
		_, err := go_openssl_EVP_DigestSignInit(ctx, nil, alg.md, nil, key)
		return err
	}); err != nil {
		return nil, err
	}
	if _, err := go_openssl_EVP_DigestUpdate(ctx, unsafe.Pointer(base(msg)), len(msg)); err != nil {
		return nil, err
	}
	// Obtain the signature length
	if _, err := go_openssl_EVP_DigestSignFinal(ctx, nil, &outLen); err != nil {
		return nil, err
	}
	out = make([]byte, outLen)
	// Obtain the signature
	if _, err := go_openssl_EVP_DigestSignFinal(ctx, base(out), &outLen); err != nil {
		return nil, err
	}
	return out[:outLen], nil
}

func evpHashVerify(withKey withKeyFunc, h crypto.Hash, msg, sig []byte) error {
	alg := loadHash(h)
	if alg == nil {
		return errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	ctx, err := go_openssl_EVP_MD_CTX_new()
	if err != nil {
		return err
	}
	defer go_openssl_EVP_MD_CTX_free(ctx)
	if err := withKey(func(key _EVP_PKEY_PTR) error {
		_, err := go_openssl_EVP_DigestVerifyInit(ctx, nil, alg.md, nil, key)
		return err
	}); err != nil {
		return err
	}
	if _, err := go_openssl_EVP_DigestUpdate(ctx, unsafe.Pointer(base(msg)), len(msg)); err != nil {
		return err
	}
	if _, err := go_openssl_EVP_DigestVerifyFinal(ctx, base(sig), len(sig)); err != nil {
		return err
	}
	return nil
}

func newEVPPKEY(key _EC_KEY_PTR) (_EVP_PKEY_PTR, error) {
	pkey, err := go_openssl_EVP_PKEY_new()
	if err != nil {
		return nil, err
	}
	if _, err := go_openssl_EVP_PKEY_assign(pkey, _EVP_PKEY_EC, unsafe.Pointer(key)); err != nil {
		go_openssl_EVP_PKEY_free(pkey)
		return nil, err
	}
	return pkey, nil
}

// getECKey returns the EC_KEY from pkey.
// If pkey does not contain an EC_KEY it panics.
// The returned key should not be freed.
func getECKey(pkey _EVP_PKEY_PTR) _EC_KEY_PTR {
	key, err := go_openssl_EVP_PKEY_get0_EC_KEY(pkey)
	if err != nil {
		panic(err)
	}
	return key
}

func newEvpFromParams(id int32, selection int32, params _OSSL_PARAM_PTR) (_EVP_PKEY_PTR, error) {
	ctx, err := go_openssl_EVP_PKEY_CTX_new_id(id, nil)
	if err != nil {
		return nil, err
	}
	defer go_openssl_EVP_PKEY_CTX_free(ctx)
	if _, err := go_openssl_EVP_PKEY_fromdata_init(ctx); err != nil {
		return nil, err
	}
	var pkey _EVP_PKEY_PTR
	if _, err := go_openssl_EVP_PKEY_fromdata(ctx, &pkey, selection, params); err != nil {
		if vMajor == 3 && vMinor <= 2 {
			// OpenSSL 3.0.1 and 3.0.2 have a bug where EVP_PKEY_fromdata
			// does not free the internally allocated EVP_PKEY on error.
			// See https://github.com/openssl/openssl/issues/17407.
			go_openssl_EVP_PKEY_free(pkey)
		}
		return nil, err
	}
	return pkey, nil
}

func checkPkey(pkey _EVP_PKEY_PTR, isPrivate bool) error {
	ctx, err := go_openssl_EVP_PKEY_CTX_new(pkey, nil)
	if err != nil {
		return err
	}
	defer go_openssl_EVP_PKEY_CTX_free(ctx)
	if isPrivate {
		if _, err := go_openssl_EVP_PKEY_private_check(ctx); err != nil {
			// Match upstream error message.
			return errors.New("invalid private key")
		}
	} else {
		// Upstream Go does a partial check here, so do we.
		if _, err := go_openssl_EVP_PKEY_public_check_quick(ctx); err != nil {
			// Match upstream error message.
			return errors.New("invalid public key")
		}
	}
	return nil
}
