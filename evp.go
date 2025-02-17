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

var (
	keyTypeRSA     = C.CString("RSA")
	keyTypeEC      = C.CString("EC")
	keyTypeED25519 = C.CString("ED25519")
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
func hashToMD(h hash.Hash) C.GO_EVP_MD_PTR {
	if h, ok := h.(*evpHash); ok {
		return h.alg.md
	}
	return nil
}

// hashFuncToMD converts a hash.Hash function to a GO_EVP_MD_PTR.
// See [hashFuncHash] for details on error handling.
func hashFuncToMD(fn func() hash.Hash) (C.GO_EVP_MD_PTR, error) {
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
	md             C.GO_EVP_MD_PTR
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
		hash.md = C.go_openssl_EVP_ripemd160()
	case crypto.MD4:
		hash.md = C.go_openssl_EVP_md4()
	case crypto.MD5:
		hash.md = C.go_openssl_EVP_md5()
		hash.magic = md5Magic
		hash.marshalledSize = md5MarshaledSize
	case crypto.MD5SHA1:
		hash.md = C.go_openssl_EVP_md5_sha1()
	case crypto.SHA1:
		hash.md = C.go_openssl_EVP_sha1()
		hash.magic = sha1Magic
		hash.marshalledSize = sha1MarshaledSize
	case crypto.SHA224:
		hash.md = C.go_openssl_EVP_sha224()
		hash.magic = magic224
		hash.marshalledSize = marshaledSize256
	case crypto.SHA256:
		hash.md = C.go_openssl_EVP_sha256()
		hash.magic = magic256
		hash.marshalledSize = marshaledSize256
	case crypto.SHA384:
		hash.md = C.go_openssl_EVP_sha384()
		hash.magic = magic384
		hash.marshalledSize = marshaledSize512
	case crypto.SHA512:
		hash.md = C.go_openssl_EVP_sha512()
		hash.magic = magic512
		hash.marshalledSize = marshaledSize512
	case crypto.SHA512_224:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = C.go_openssl_EVP_sha512_224()
			hash.magic = magic512_224
			hash.marshalledSize = marshaledSize512
		}
	case crypto.SHA512_256:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = C.go_openssl_EVP_sha512_256()
			hash.magic = magic512_256
			hash.marshalledSize = marshaledSize512
		}
	case crypto.SHA3_224:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = C.go_openssl_EVP_sha3_224()
		}
	case crypto.SHA3_256:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = C.go_openssl_EVP_sha3_256()
		}
	case crypto.SHA3_384:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = C.go_openssl_EVP_sha3_384()
		}
	case crypto.SHA3_512:
		if versionAtOrAbove(1, 1, 1) {
			hash.md = C.go_openssl_EVP_sha3_512()
		}
	}
	if hash.md == nil {
		cacheMD.Store(ch, (*hashAlgorithm)(nil))
		return nil
	}
	hash.ch = ch
	hash.size = int(C.go_openssl_EVP_MD_get_size(hash.md))
	hash.blockSize = int(C.go_openssl_EVP_MD_get_block_size(hash.md))
	if vMajor == 3 {
		// On OpenSSL 3, directly operating on a EVP_MD object
		// not created by EVP_MD_fetch has negative performance
		// implications, as digest operations will have
		// to fetch it on every call. Better to just fetch it once here.
		md := C.go_openssl_EVP_MD_fetch(nil, C.go_openssl_EVP_MD_get0_name(hash.md), nil)
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
func generateEVPPKey(id C.int, bits int, curve string) (C.GO_EVP_PKEY_PTR, error) {
	if bits != 0 && curve != "" {
		return nil, fail("incorrect generateEVPPKey parameters")
	}
	var pkey C.GO_EVP_PKEY_PTR
	switch vMajor {
	case 1:
		ctx := C.go_openssl_EVP_PKEY_CTX_new_id(id, nil)
		if ctx == nil {
			return nil, newOpenSSLError("EVP_PKEY_CTX_new_id")
		}
		defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
		if C.go_openssl_EVP_PKEY_keygen_init(ctx) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_keygen_init")
		}
		if bits != 0 {
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, id, -1, C.GO_EVP_PKEY_CTRL_RSA_KEYGEN_BITS, C.int(bits), nil) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl")
			}
		}
		if curve != "" {
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, id, -1, C.GO_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, curveNID(curve), nil) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl")
			}
		}
		if C.go_openssl_EVP_PKEY_keygen(ctx, &pkey) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_keygen")
		}
	case 3:
		switch id {
		case C.GO_EVP_PKEY_RSA:
			pkey = C.go_openssl_EVP_PKEY_Q_keygen_RSA(nil, nil, keyTypeRSA, C.size_t(bits))
		case C.GO_EVP_PKEY_EC:
			pkey = C.go_openssl_EVP_PKEY_Q_keygen_EC(nil, nil, keyTypeEC, C.go_openssl_OBJ_nid2sn(curveNID(curve)))
		case C.GO_EVP_PKEY_ED25519:
			pkey = C.go_openssl_EVP_PKEY_Q_keygen(nil, nil, keyTypeED25519)
		default:
			panic("unsupported key type '" + strconv.Itoa(int(id)) + "'")
		}
		if pkey == nil {
			return nil, newOpenSSLError("EVP_PKEY_Q_keygen")
		}
	default:
		panic(errUnsupportedVersion())
	}

	return pkey, nil
}

type withKeyFunc func(func(C.GO_EVP_PKEY_PTR) C.int) C.int
type initFunc func(C.GO_EVP_PKEY_CTX_PTR) error
type cryptFunc func(C.GO_EVP_PKEY_CTX_PTR, *C.uchar, *C.size_t, *C.uchar, C.size_t) error
type verifyFunc func(C.GO_EVP_PKEY_CTX_PTR, *C.uchar, C.size_t, *C.uchar, C.size_t) error

func setupEVP(withKey withKeyFunc, padding C.int,
	h, mgfHash hash.Hash, label []byte, saltLen C.int, ch crypto.Hash,
	init initFunc) (_ C.GO_EVP_PKEY_CTX_PTR, err error) {
	var ctx C.GO_EVP_PKEY_CTX_PTR
	withKey(func(pkey C.GO_EVP_PKEY_PTR) C.int {
		ctx = C.go_openssl_EVP_PKEY_CTX_new(pkey, nil)
		return 1
	})
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new failed")
	}
	defer func() {
		if err != nil {
			if ctx != nil {
				C.go_openssl_EVP_PKEY_CTX_free(ctx)
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
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_PADDING, padding, nil) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
		return nil
	}
	switch padding {
	case C.GO_RSA_PKCS1_OAEP_PADDING:
		md := hashToMD(h)
		if md == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		var mgfMD C.GO_EVP_MD_PTR
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
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_OAEP_MD, 0, unsafe.Pointer(md)) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
		if mgfHash != nil {
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_MGF1_MD, 0, unsafe.Pointer(mgfMD)) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
			}
		}
		// ctx takes ownership of label, so malloc a copy for OpenSSL to free.
		// OpenSSL does not take ownership of the label if the length is zero,
		// so better avoid the allocation.
		var clabel *C.uchar
		if len(label) > 0 {
			clabel = (*C.uchar)(cryptoMalloc(len(label)))
			copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
			var err error
			if vMajor == 3 {
				ret := C.go_openssl_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, unsafe.Pointer(clabel), C.int(len(label)))
				if ret != 1 {
					err = newOpenSSLError("EVP_PKEY_CTX_set0_rsa_oaep_label failed")
				}
			} else {
				ret := C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_OAEP_LABEL, C.int(len(label)), unsafe.Pointer(clabel))
				if ret != 1 {
					err = newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
				}
			}
			if err != nil {
				cryptoFree(unsafe.Pointer(clabel))
				return nil, err
			}
		}
	case C.GO_RSA_PKCS1_PSS_PADDING:
		alg := loadHash(ch)
		if alg == nil {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(alg.md)) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
		}
		// setPadding must happen after setting EVP_PKEY_CTRL_MD.
		if err := setPadding(); err != nil {
			return nil, err
		}
		if saltLen != 0 {
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltLen, nil) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
			}
		}

	case C.GO_RSA_PKCS1_PADDING:
		if ch != 0 {
			// We support unhashed messages.
			alg := loadHash(ch)
			if alg == nil {
				return nil, errors.New("crypto/rsa: unsupported hash function")
			}
			if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx, -1, -1, C.GO_EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(alg.md)) != 1 {
				return nil, newOpenSSLError("EVP_PKEY_CTX_ctrl failed")
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

func cryptEVP(withKey withKeyFunc, padding C.int,
	h, mgfHash hash.Hash, label []byte, saltLen C.int, ch crypto.Hash,
	init initFunc, crypt cryptFunc, in []byte) ([]byte, error) {

	ctx, err := setupEVP(withKey, padding, h, mgfHash, label, saltLen, ch, init)
	if err != nil {
		return nil, err
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	pkeySize := withKey(func(pkey C.GO_EVP_PKEY_PTR) C.int {
		return C.go_openssl_EVP_PKEY_get_size(pkey)
	})
	outLen := C.size_t(pkeySize)
	out := make([]byte, pkeySize)
	if err := crypt(ctx, base(out), &outLen, base(in), C.size_t(len(in))); err != nil {
		return nil, err
	}
	// The size returned by EVP_PKEY_get_size() is only preliminary and not exact,
	// so the final contents of the out buffer may be smaller.
	return out[:outLen], nil
}

func verifyEVP(withKey withKeyFunc, padding C.int,
	h hash.Hash, label []byte, saltLen C.int, ch crypto.Hash,
	init initFunc, verify verifyFunc,
	sig, in []byte) error {

	ctx, err := setupEVP(withKey, padding, h, nil, label, saltLen, ch, init)
	if err != nil {
		return err
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	return verify(ctx, base(sig), C.size_t(len(sig)), base(in), C.size_t(len(in)))
}

func evpEncrypt(withKey withKeyFunc, padding C.int, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	encryptInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) error {
		if ret := C.go_openssl_EVP_PKEY_encrypt_init(ctx); ret != 1 {
			return newOpenSSLError("EVP_PKEY_encrypt_init failed")
		}
		return nil
	}
	encrypt := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uchar, outLen *C.size_t, in *C.uchar, inLen C.size_t) error {
		if ret := C.go_openssl_EVP_PKEY_encrypt(ctx, out, outLen, in, inLen); ret != 1 {
			return newOpenSSLError("EVP_PKEY_encrypt failed")
		}
		return nil
	}
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, encryptInit, encrypt, msg)
}

func evpDecrypt(withKey withKeyFunc, padding C.int, h, mgfHash hash.Hash, label, msg []byte) ([]byte, error) {
	decryptInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) error {
		if ret := C.go_openssl_EVP_PKEY_decrypt_init(ctx); ret != 1 {
			return newOpenSSLError("EVP_PKEY_decrypt_init failed")
		}
		return nil
	}
	decrypt := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uchar, outLen *C.size_t, in *C.uchar, inLen C.size_t) error {
		if ret := C.go_openssl_EVP_PKEY_decrypt(ctx, out, outLen, in, inLen); ret != 1 {
			return newOpenSSLError("EVP_PKEY_decrypt failed")
		}
		return nil
	}
	return cryptEVP(withKey, padding, h, mgfHash, label, 0, 0, decryptInit, decrypt, msg)
}

func evpSign(withKey withKeyFunc, padding C.int, saltLen C.int, h crypto.Hash, hashed []byte) ([]byte, error) {
	signtInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) error {
		if ret := C.go_openssl_EVP_PKEY_sign_init(ctx); ret != 1 {
			return newOpenSSLError("EVP_PKEY_sign_init failed")
		}
		return nil
	}
	sign := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uchar, outLen *C.size_t, in *C.uchar, inLen C.size_t) error {
		if ret := C.go_openssl_EVP_PKEY_sign(ctx, out, outLen, in, inLen); ret != 1 {
			return newOpenSSLError("EVP_PKEY_sign failed")
		}
		return nil
	}
	return cryptEVP(withKey, padding, nil, nil, nil, saltLen, h, signtInit, sign, hashed)
}

func evpVerify(withKey withKeyFunc, padding C.int, saltLen C.int, h crypto.Hash, sig, hashed []byte) error {
	verifyInit := func(ctx C.GO_EVP_PKEY_CTX_PTR) error {
		if ret := C.go_openssl_EVP_PKEY_verify_init(ctx); ret != 1 {
			return newOpenSSLError("EVP_PKEY_verify_init failed")
		}
		return nil
	}
	verify := func(ctx C.GO_EVP_PKEY_CTX_PTR, out *C.uchar, outLen C.size_t, in *C.uchar, inLen C.size_t) error {
		if ret := C.go_openssl_EVP_PKEY_verify(ctx, out, outLen, in, inLen); ret != 1 {
			return newOpenSSLError("EVP_PKEY_verify failed")
		}
		return nil
	}
	return verifyEVP(withKey, padding, nil, nil, saltLen, h, verifyInit, verify, sig, hashed)
}

func evpHashSign(withKey withKeyFunc, h crypto.Hash, msg []byte) ([]byte, error) {
	alg := loadHash(h)
	if alg == nil {
		return nil, errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	var out []byte
	var outLen C.size_t
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return nil, newOpenSSLError("EVP_MD_CTX_new failed")
	}
	defer C.go_openssl_EVP_MD_CTX_free(ctx)
	if withKey(func(key C.GO_EVP_PKEY_PTR) C.int {
		return C.go_openssl_EVP_DigestSignInit(ctx, nil, alg.md, nil, key)
	}) != 1 {
		return nil, newOpenSSLError("EVP_DigestSignInit failed")
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
	alg := loadHash(h)
	if alg == nil {
		return errors.New("unsupported hash function: " + strconv.Itoa(int(h)))
	}
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return newOpenSSLError("EVP_MD_CTX_new failed")
	}
	defer C.go_openssl_EVP_MD_CTX_free(ctx)
	if withKey(func(key C.GO_EVP_PKEY_PTR) C.int {
		return C.go_openssl_EVP_DigestVerifyInit(ctx, nil, alg.md, nil, key)
	}) != 1 {
		return newOpenSSLError("EVP_DigestVerifyInit failed")
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
func getECKey(pkey C.GO_EVP_PKEY_PTR) C.GO_EC_KEY_PTR {
	key := C.go_openssl_EVP_PKEY_get0_EC_KEY(pkey)
	if key == nil {
		panic("pkey does not contain an EC_KEY")
	}
	return key
}

func newEvpFromParams(id C.int, selection C.int, params C.GO_OSSL_PARAM_PTR) (C.GO_EVP_PKEY_PTR, error) {
	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(id, nil)
	if ctx == nil {
		return nil, newOpenSSLError("EVP_PKEY_CTX_new_id")
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	if C.go_openssl_EVP_PKEY_fromdata_init(ctx) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_fromdata_init")
	}
	var pkey C.GO_EVP_PKEY_PTR
	if C.go_openssl_EVP_PKEY_fromdata(ctx, &pkey, selection, params) != 1 {
		if vMajor == 3 && vMinor <= 2 {
			// OpenSSL 3.0.1 and 3.0.2 have a bug where EVP_PKEY_fromdata
			// does not free the internally allocated EVP_PKEY on error.
			// See https://github.com/openssl/openssl/issues/17407.
			C.go_openssl_EVP_PKEY_free(pkey)
		}
		return nil, newOpenSSLError("EVP_PKEY_fromdata")
	}
	return pkey, nil
}

func checkPkey(pkey C.GO_EVP_PKEY_PTR, isPrivate bool) error {
	ctx := C.go_openssl_EVP_PKEY_CTX_new(pkey, nil)
	if ctx == nil {
		return newOpenSSLError("EVP_PKEY_CTX_new")
	}
	defer C.go_openssl_EVP_PKEY_CTX_free(ctx)
	if isPrivate {
		if C.go_openssl_EVP_PKEY_private_check(ctx) != 1 {
			// Match upstream error message.
			return errors.New("invalid private key")
		}
	} else {
		// Upstream Go does a partial check here, so do we.
		if C.go_openssl_EVP_PKEY_public_check_quick(ctx) != 1 {
			// Match upstream error message.
			return errors.New("invalid public key")
		}
	}
	return nil
}
