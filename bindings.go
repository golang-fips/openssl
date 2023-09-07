//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import "unsafe"

type evpPkeyCtx struct {
	ptr C.GO_EVP_PKEY_CTX_PTR
}

func newEvpPkeyCtx(pkey C.GO_EVP_PKEY_PTR) (evpPkeyCtx, error) {
	ctx := C.go_openssl_EVP_PKEY_CTX_new(pkey, nil)
	if ctx == nil {
		return evpPkeyCtx{}, newOpenSSLError("EVP_PKEY_CTX_new")
	}
	return evpPkeyCtx{ctx}, nil
}

func newEvpPkeyCtxFromID(id int) (evpPkeyCtx, error) {
	ctx := C.go_openssl_EVP_PKEY_CTX_new_id(C.int(id), nil)
	if ctx == nil {
		return evpPkeyCtx{}, newOpenSSLError("EVP_PKEY_CTX_new_id")
	}
	return evpPkeyCtx{ctx}, nil
}

func (ctx evpPkeyCtx) free() {
	if ctx.ptr != nil {
		C.go_openssl_EVP_PKEY_CTX_free(ctx.ptr)
	}
}

func (ctx evpPkeyCtx) ctrl(keytype int, optype int, cmd int, p1 int, p2 unsafe.Pointer) error {
	if C.go_openssl_EVP_PKEY_CTX_ctrl(ctx.ptr, C.int(keytype), C.int(optype), C.int(cmd), C.int(p1), p2) != 1 {
		return newOpenSSLError("EVP_PKEY_CTX_ctrl")
	}
	return nil
}

func (ctx evpPkeyCtx) keygenInit() error {
	if C.go_openssl_EVP_PKEY_keygen_init(ctx.ptr) != 1 {
		return newOpenSSLError("EVP_PKEY_keygen_init")
	}
	return nil
}

func (ctx evpPkeyCtx) keygen() (pkey C.GO_EVP_PKEY_PTR, err error) {
	if C.go_openssl_EVP_PKEY_keygen(ctx.ptr, &pkey) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_keygen")
	}
	return pkey, nil
}

func (ctx evpPkeyCtx) encryptInit() error {
	if C.go_openssl_EVP_PKEY_encrypt_init(ctx.ptr) != 1 {
		return newOpenSSLError("EVP_PKEY_encrypt_init")
	}
	return nil
}

func (ctx evpPkeyCtx) encrypt(out []byte, in []byte) ([]byte, error) {
	outLen := C.size_t(len(out))
	if ret := C.go_openssl_EVP_PKEY_encrypt(ctx.ptr, base(out), &outLen, base(in), C.size_t(len(in))); ret != 1 {
		return nil, newOpenSSLError("EVP_PKEY_encrypt")
	}
	return out[:outLen], nil
}

func (ctx evpPkeyCtx) decryptInit() error {
	if C.go_openssl_EVP_PKEY_decrypt_init(ctx.ptr) != 1 {
		return newOpenSSLError("EVP_PKEY_decrypt_init")
	}
	return nil
}

func (ctx evpPkeyCtx) decrypt(out []byte, in []byte) ([]byte, error) {
	outLen := C.size_t(len(out))
	if ret := C.go_openssl_EVP_PKEY_decrypt(ctx.ptr, base(out), &outLen, base(in), C.size_t(len(in))); ret != 1 {
		return nil, newOpenSSLError("EVP_PKEY_decrypt")
	}
	return out[:outLen], nil
}

func (ctx evpPkeyCtx) signInit() error {
	if C.go_openssl_EVP_PKEY_sign_init(ctx.ptr) != 1 {
		return newOpenSSLError("EVP_PKEY_sign_init")
	}
	return nil
}

func (ctx evpPkeyCtx) sign(out []byte, in []byte) ([]byte, error) {
	outLen := C.size_t(len(out))
	if ret := C.go_openssl_EVP_PKEY_sign(ctx.ptr, base(out), &outLen, base(in), C.size_t(len(in))); ret != 1 {
		return nil, newOpenSSLError("EVP_PKEY_sign")
	}
	return out[:outLen], nil
}

func (ctx evpPkeyCtx) verifyInit() error {
	if C.go_openssl_EVP_PKEY_verify_init(ctx.ptr) != 1 {
		return newOpenSSLError("EVP_PKEY_verify_init")
	}
	return nil
}

func (ctx evpPkeyCtx) verify(sig []byte, in []byte) error {
	if ret := C.go_openssl_EVP_PKEY_verify(ctx.ptr, base(sig), C.size_t(len(sig)), base(in), C.size_t(len(in))); ret != 1 {
		return newOpenSSLError("EVP_PKEY_verify")
	}
	return nil
}

func (ctx evpPkeyCtx) fromdataInit() error {
	if C.go_openssl_EVP_PKEY_fromdata_init(ctx.ptr) != 1 {
		return newOpenSSLError("EVP_PKEY_fromdata_init")
	}
	return nil
}

func (ctx evpPkeyCtx) fromdata(selection int, params C.GO_OSSL_PARAM_PTR) (pkey C.GO_EVP_PKEY_PTR, err error) {
	if C.go_openssl_EVP_PKEY_fromdata(ctx.ptr, &pkey, C.int(selection), params) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_fromdata")
	}
	return pkey, nil
}

func (ctx evpPkeyCtx) deriveInit() error {
	if C.go_openssl_EVP_PKEY_derive_init(ctx.ptr) != 1 {
		return newOpenSSLError("EVP_PKEY_derive_init")
	}
	return nil
}

func (ctx evpPkeyCtx) deriveSetPeer(peer C.GO_EVP_PKEY_PTR) error {
	if C.go_openssl_EVP_PKEY_derive_set_peer(ctx.ptr, peer) != 1 {
		return newOpenSSLError("EVP_PKEY_derive_set_peer")
	}
	return nil
}

func (ctx evpPkeyCtx) derive(out []byte) ([]byte, error) {
	outLen := C.size_t(len(out))
	if out == nil {
		if C.go_openssl_EVP_PKEY_derive(ctx.ptr, nil, &outLen) != 1 {
			return nil, newOpenSSLError("EVP_PKEY_derive")
		}
		out = make([]byte, outLen)
	}
	if C.go_openssl_EVP_PKEY_derive(ctx.ptr, base(out), &outLen) != 1 {
		return nil, newOpenSSLError("EVP_PKEY_derive")
	}
	return out[:outLen], nil
}

func (ctx evpPkeyCtx) setHKDFProps(mode int, md C.GO_EVP_MD_PTR, key []byte, salt []byte, info []byte) error {
	switch vMajor {
	case 3:
		if mode != 0 {
			if C.go_openssl_EVP_PKEY_CTX_set_hkdf_mode(ctx.ptr, C.int(mode)) != 1 {
				return newOpenSSLError("EVP_PKEY_CTX_set_hkdf_mode")
			}
		}
		if md != nil {
			if C.go_openssl_EVP_PKEY_CTX_set_hkdf_md(ctx.ptr, md) != 1 {
				return newOpenSSLError("EVP_PKEY_CTX_set_hkdf_md")
			}
		}
		if key != nil {
			if C.go_openssl_EVP_PKEY_CTX_set1_hkdf_key(ctx.ptr, base(key), C.int(len(key))) != 1 {
				return newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_key")
			}
		}
		if salt != nil {
			if C.go_openssl_EVP_PKEY_CTX_set1_hkdf_salt(ctx.ptr, base(salt), C.int(len(salt))) != 1 {
				return newOpenSSLError("EVP_PKEY_CTX_set1_hkdf_salt")
			}
		}
		if info != nil {
			if C.go_openssl_EVP_PKEY_CTX_add1_hkdf_info(ctx.ptr, base(info), C.int(len(info))) != 1 {
				return newOpenSSLError("EVP_PKEY_CTX_add1_hkdf_info")
			}
		}
		return nil
	case 1:
		if mode != 0 {
			if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_HKDF_MODE, mode, nil); err != nil {
				return err
			}
		}
		if md != nil {
			if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_HKDF_MD, 0, unsafe.Pointer(md)); err != nil {
				return err
			}
		}
		if key != nil {
			if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_HKDF_KEY, len(key), unsafe.Pointer(base(key))); err != nil {
				return err
			}
		}
		if salt != nil {
			if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_HKDF_SALT, len(salt), unsafe.Pointer(base(salt))); err != nil {
				return err
			}
		}
		if info != nil {
			if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_HKDF_INFO, len(info), unsafe.Pointer(base(info))); err != nil {
				return err
			}
		}
	default:
		panic(errUnsupportedVersion())
	}
	return nil
}

func (ctx evpPkeyCtx) setTLS1PRFProps(md C.GO_EVP_MD_PTR, secret []byte, seeds ...[]byte) error {

	switch vMajor {
	case 3:
		if C.go_openssl_EVP_PKEY_CTX_set_tls1_prf_md(ctx.ptr, md) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_set_tls1_prf_md")
		}
		if C.go_openssl_EVP_PKEY_CTX_set1_tls1_prf_secret(ctx.ptr, base(secret), C.int(len(secret))) != 1 {
			return newOpenSSLError("EVP_PKEY_CTX_set1_tls1_prf_secret")
		}
		for _, s := range seeds {
			if C.go_openssl_EVP_PKEY_CTX_add1_tls1_prf_seed(ctx.ptr, base(s), C.int(len(s))) != 1 {
				return newOpenSSLError("EVP_PKEY_CTX_add1_tls1_prf_seed")
			}
		}
	case 1:
		if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_TLS_MD, 0, unsafe.Pointer(md)); err != nil {
			return err
		}
		if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_TLS_SECRET, len(secret), unsafe.Pointer(base(secret))); err != nil {
			return err
		}
		for _, s := range seeds {
			if err := ctx.ctrl(-1, C.GO1_EVP_PKEY_OP_DERIVE, C.GO_EVP_PKEY_CTRL_TLS_SEED, len(s), unsafe.Pointer(base(s))); err != nil {
				return err
			}
		}
	default:
		panic(errUnsupportedVersion())
	}
	return nil
}

func (ctx evpPkeyCtx) setRSAOAEPLabel(label []byte) error {
	// ctx takes ownership of label, so malloc a copy for OpenSSL to free.
	// OpenSSL does not take ownership of the label if the length is zero,
	// so better avoid the allocation.
	var clabel *C.uchar
	if len(label) > 0 {
		clabel = (*C.uchar)(cryptoMalloc(len(label)))
		copy((*[1 << 30]byte)(unsafe.Pointer(clabel))[:len(label)], label)
	}
	switch vMajor {
	case 3:
		if C.go_openssl_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.ptr, unsafe.Pointer(clabel), C.int(len(label))) != 1 {
			cryptoFree(unsafe.Pointer(clabel))
			return newOpenSSLError("EVP_PKEY_CTX_set0_rsa_oaep_label")
		}
	case 1:
		if err := ctx.ctrl(C.GO_EVP_PKEY_RSA, -1, C.GO_EVP_PKEY_CTRL_RSA_OAEP_LABEL, len(label), unsafe.Pointer(clabel)); err != nil {
			cryptoFree(unsafe.Pointer(clabel))
			return err
		}
	default:
		panic(errUnsupportedVersion())
	}
	return nil
}
