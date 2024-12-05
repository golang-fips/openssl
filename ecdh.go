//go:build !cmd_go_bootstrap && cgo

package openssl

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

type PublicKeyECDH struct {
	_pkey ossl.EVP_PKEY_PTR
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

type PrivateKeyECDH struct {
	_pkey        ossl.EVP_PKEY_PTR
	curve        string
	hasPublicKey bool
}

func (k *PrivateKeyECDH) finalize() {
	ossl.EVP_PKEY_free(k._pkey)
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) < 1 {
		return nil, errors.New("NewPublicKeyECDH: missing key")
	}
	pkey, err := newECDHPkey(curve, bytes, false)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDH{pkey, append([]byte(nil), bytes...)}
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	pkey, err := newECDHPkey(curve, bytes, true)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDH{pkey, curve, false}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	if !k.hasPublicKey {
		err := deriveEcdhPublicKey(k._pkey, k.curve)
		if err != nil {
			return nil, err
		}
		k.hasPublicKey = true
	}
	var pkey ossl.EVP_PKEY_PTR
	defer func() {
		ossl.EVP_PKEY_free(pkey)
	}()

	var bytes []byte
	switch vMajor {
	case 1:
		var err error
		pkey, err = ossl.EVP_PKEY_new()
		if err != nil {
			return nil, err
		}
		key := getECKey(k._pkey)
		if err := ossl.EVP_PKEY_set1_EC_KEY(pkey, key); err != nil {
			return nil, err
		}
		pt, err := ossl.EC_KEY_get0_public_key(key)
		if err != nil {
			return nil, err
		}
		group, err := ossl.EC_KEY_get0_group(key)
		if err != nil {
			return nil, err
		}
		bytes, err = encodeEcPoint(group, pt)
		if err != nil {
			return nil, err
		}
	case 3:
		pkey = k._pkey
		if err := ossl.EVP_PKEY_up_ref(pkey); err != nil {
			return nil, err
		}

		var cbytes *byte
		n, err := ossl.EVP_PKEY_get1_encoded_public_key(k._pkey, &cbytes)
		if err != nil {
			return nil, err
		}
		bytes = make([]byte, n)
		copy(bytes, unsafe.Slice(cbytes, n))
		cryptoFree(unsafe.Pointer(cbytes))
	default:
		panic(errUnsupportedVersion())
	}
	pub := &PublicKeyECDH{pkey, bytes}
	pkey = nil
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}

func newECDHPkey(curve string, bytes []byte, isPrivate bool) (ossl.EVP_PKEY_PTR, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	switch vMajor {
	case 1:
		return newECDHPkey1(nid, bytes, isPrivate)
	case 3:
		return newECDHPkey3(nid, bytes, isPrivate)
	default:
		panic(errUnsupportedVersion())
	}
}

func newECDHPkey1(nid int, bytes []byte, isPrivate bool) (pkey ossl.EVP_PKEY_PTR, err error) {
	checkMajorVersion(1)

	key, err := ossl.EC_KEY_new_by_curve_name(int32(nid))
	if err != nil {
		return nil, err
	}
	defer func() {
		if pkey == nil {
			ossl.EC_KEY_free(key)
		}
	}()
	if isPrivate {
		priv, err := ossl.BN_bin2bn(base(bytes), int32(len(bytes)), nil)
		if err != nil {
			return nil, err
		}
		defer ossl.BN_clear_free(priv)
		if err := ossl.EC_KEY_set_private_key(key, priv); err != nil {
			return nil, err
		}
	} else {
		group, err := ossl.EC_KEY_get0_group(key)
		if err != nil {
			return nil, err
		}
		pub, err := ossl.EC_POINT_new(group)
		if err != nil {
			return nil, err
		}
		defer ossl.EC_POINT_free(pub)
		if ossl.EC_POINT_oct2point(group, pub, base(bytes), len(bytes), nil) != nil {
			return nil, errors.New("point not on curve")
		}
		if err := ossl.EC_KEY_set_public_key(key, pub); err != nil {
			return nil, err
		}
	}
	return newEVPPKEY(key)
}

func newECDHPkey3(nid int, bytes []byte, isPrivate bool) (ossl.EVP_PKEY_PTR, error) {
	checkMajorVersion(3)

	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()
	bld.addUTF8String(ossl.OSSL_PKEY_PARAM_GROUP_NAME, ossl.OBJ_nid2sn(int32(nid)), 0)
	var selection int
	if isPrivate {
		bld.addBin(ossl.OSSL_PKEY_PARAM_PRIV_KEY, bytes, true)
		selection = ossl.EVP_PKEY_KEYPAIR
	} else {
		bld.addOctetString(ossl.OSSL_PKEY_PARAM_PUB_KEY, bytes)
		selection = ossl.EVP_PKEY_PUBLIC_KEY
	}

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)
	return newEvpFromParams(ossl.EVP_PKEY_EC, selection, params)
}

// deriveEcdhPublicKey sets the raw public key of pkey by deriving it from
// the raw private key.
func deriveEcdhPublicKey(pkey ossl.EVP_PKEY_PTR, curve string) error {
	derive := func(group ossl.EC_GROUP_PTR, priv ossl.BIGNUM_PTR) (ossl.EC_POINT_PTR, error) {
		// OpenSSL does not expose any method to generate the public
		// key from the private key [1], so we have to calculate it here.
		// [1] https://github.com/openssl/openssl/issues/18437#issuecomment-1144717206
		pt, err := ossl.EC_POINT_new(group)
		if err != nil {
			return nil, err
		}
		if err := ossl.EC_POINT_mul(group, pt, priv, nil, nil, nil); err != nil {
			ossl.EC_POINT_free(pt)
			return nil, err
		}
		return pt, nil
	}
	switch vMajor {
	case 1:
		key := getECKey(pkey)
		priv, err := ossl.EC_KEY_get0_private_key(key)
		if err != nil {
			return err
		}
		group, err := ossl.EC_KEY_get0_group(key)
		if err != nil {
			return err
		}
		pub, err := derive(group, priv)
		if err != nil {
			return err
		}
		defer ossl.EC_POINT_free(pub)
		if err := ossl.EC_KEY_set_public_key(key, pub); err != nil {
			return err
		}
	case 3:
		var priv ossl.BIGNUM_PTR
		if err := getBnParam(pkey, ossl.OSSL_PKEY_PARAM_PRIV_KEY, &priv); err != nil {
			return err
		}
		defer ossl.BN_clear_free(priv)
		nid, _ := curveNID(curve)
		pubBytes, err := generateAndEncodeEcPublicKey(nid, func(group ossl.EC_GROUP_PTR) (ossl.EC_POINT_PTR, error) {
			return derive(group, priv)
		})
		if err != nil {
			return err
		}
		if err := ossl.EVP_PKEY_set1_encoded_public_key(pkey, base(pubBytes), len(pubBytes)); err != nil {
			return err
		}
	default:
		panic(errUnsupportedVersion())
	}
	return nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	defer runtime.KeepAlive(pub)
	ctx, err := ossl.EVP_PKEY_CTX_new(priv._pkey, nil)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)
	if err := ossl.EVP_PKEY_derive_init(ctx); err != nil {
		return nil, err
	}
	if err := ossl.EVP_PKEY_derive_set_peer(ctx, pub._pkey); err != nil {
		return nil, err
	}
	keyLength, err := ossl.EVP_PKEY_derive_wrapper(ctx, nil, 0)
	if err != nil {
		return nil, err
	}
	out := make([]byte, keyLength)
	if _, err := ossl.EVP_PKEY_derive_wrapper(ctx, base(out), keyLength); err != nil {
		return nil, err
	}
	return out, nil
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	pkey, err := generateEVPPKey(ossl.EVP_PKEY_EC, 0, curve)
	if err != nil {
		return nil, nil, err
	}
	var k *PrivateKeyECDH
	defer func() {
		if k == nil {
			ossl.EVP_PKEY_free(pkey)
		}
	}()
	var priv ossl.BIGNUM_PTR
	switch vMajor {
	case 1:
		key := getECKey(pkey)
		priv, err = ossl.EC_KEY_get0_private_key(key)
		if err != nil {
			return nil, nil, err
		}
	case 3:
		if err := getBnParam(pkey, ossl.OSSL_PKEY_PARAM_PRIV_KEY, &priv); err != nil {
			return nil, nil, err
		}
		defer ossl.BN_clear_free(priv)
	default:
		panic(errUnsupportedVersion())
	}
	// We should not leak bit length of the secret scalar in the key.
	// For this reason, we use BN_bn2binpad instead of BN_bn2bin with fixed length.
	// The fixed length is the order of the large prime subgroup of the curve,
	// returned by EVP_PKEY_get_bits, which is generally the upper bound for
	// generating a private ECDH key.
	bits := ossl.EVP_PKEY_get_bits(pkey)
	bytes := make([]byte, (bits+7)/8)
	if err := bnToBinPad(priv, bytes); err != nil {
		return nil, nil, err
	}
	k = &PrivateKeyECDH{pkey, curve, true}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}
