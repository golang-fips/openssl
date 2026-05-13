//go:build !cmd_go_bootstrap

package openssl

import (
	"errors"
	"sync"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

const (
	// privateKeySizeMLDSA is the size of an ML-DSA private key seed.
	privateKeySizeMLDSA = 32

	// publicKeySizeMLDSA44 is the size of an ML-DSA-44 public key encoding.
	publicKeySizeMLDSA44 = 1312

	// publicKeySizeMLDSA65 is the size of an ML-DSA-65 public key encoding.
	publicKeySizeMLDSA65 = 1952

	// publicKeySizeMLDSA87 is the size of an ML-DSA-87 public key encoding.
	publicKeySizeMLDSA87 = 2592

	// signatureSizeMLDSA44 is the size of an ML-DSA-44 signature.
	signatureSizeMLDSA44 = 2420

	// signatureSizeMLDSA65 is the size of an ML-DSA-65 signature.
	signatureSizeMLDSA65 = 3309

	// signatureSizeMLDSA87 is the size of an ML-DSA-87 signature.
	signatureSizeMLDSA87 = 4627

	// muSizeMLDSA is the size of the pre-hashed mu input to the external-mu
	// variants of Sign and Verify.
	muSizeMLDSA = 64

	// maxContextSizeMLDSA is the maximum allowed length of the context string
	// passed to Sign and Verify.
	maxContextSizeMLDSA = 255
)

// SupportsMLDSA returns true if the given ML-DSA parameter set is supported
// on this platform. Providers may not implement every security level, so
// callers must probe each parameter set they intend to use.
func SupportsMLDSA(params MLDSAParameters) bool {
	switch params.keyType {
	case ossl.EVP_PKEY_ML_DSA_44:
		return supportsMLDSA44()
	case ossl.EVP_PKEY_ML_DSA_65:
		return supportsMLDSA65()
	case ossl.EVP_PKEY_ML_DSA_87:
		return supportsMLDSA87()
	default:
		return false
	}
}

// probeMLDSA reports whether the OpenSSL provider exposes the given ML-DSA
// algorithm via the keymgmt fetch interface. ML-DSA was added in OpenSSL 3.5;
// older 3.x releases return nil for unknown algorithm names, and 1.x lacks
// the fetch interface entirely.
func probeMLDSA(name cString) bool {
	if !ossl.EVP_KEYMGMT_fetch_Available() {
		return false
	}
	mgmt, _ := ossl.EVP_KEYMGMT_fetch(nil, name.ptr(), nil)
	if mgmt == nil {
		return false
	}
	ossl.EVP_KEYMGMT_free(mgmt)
	return true
}

var (
	supportsMLDSA44 = sync.OnceValue(func() bool { return probeMLDSA(_KeyTypeMLDSA44) })
	supportsMLDSA65 = sync.OnceValue(func() bool { return probeMLDSA(_KeyTypeMLDSA65) })
	supportsMLDSA87 = sync.OnceValue(func() bool { return probeMLDSA(_KeyTypeMLDSA87) })
)

// MLDSAParameters represents one of the fixed ML-DSA parameter sets.
type MLDSAParameters struct {
	name          string
	keyType       int32
	keyTypeName   cString
	publicKeySize int
	signatureSize int
}

var (
	mldsa44 = MLDSAParameters{
		name:          "ML-DSA-44",
		keyType:       ossl.EVP_PKEY_ML_DSA_44,
		keyTypeName:   _KeyTypeMLDSA44,
		publicKeySize: publicKeySizeMLDSA44,
		signatureSize: signatureSizeMLDSA44,
	}
	mldsa65 = MLDSAParameters{
		name:          "ML-DSA-65",
		keyType:       ossl.EVP_PKEY_ML_DSA_65,
		keyTypeName:   _KeyTypeMLDSA65,
		publicKeySize: publicKeySizeMLDSA65,
		signatureSize: signatureSizeMLDSA65,
	}
	mldsa87 = MLDSAParameters{
		name:          "ML-DSA-87",
		keyType:       ossl.EVP_PKEY_ML_DSA_87,
		keyTypeName:   _KeyTypeMLDSA87,
		publicKeySize: publicKeySizeMLDSA87,
		signatureSize: signatureSizeMLDSA87,
	}
)

// MLDSA44 returns the ML-DSA-44 parameter set.
func MLDSA44() MLDSAParameters { return mldsa44 }

// MLDSA65 returns the ML-DSA-65 parameter set.
func MLDSA65() MLDSAParameters { return mldsa65 }

// MLDSA87 returns the ML-DSA-87 parameter set.
func MLDSA87() MLDSAParameters { return mldsa87 }

func (params MLDSAParameters) valid() bool {
	switch params {
	case mldsa44, mldsa65, mldsa87:
		return true
	default:
		return false
	}
}

// PublicKeySize returns the size of public keys for this parameter set, in bytes.
func (params MLDSAParameters) PublicKeySize() int { return params.publicKeySize }

// SignatureSize returns the size of signatures for this parameter set, in bytes.
func (params MLDSAParameters) SignatureSize() int { return params.signatureSize }

// String returns the name of the parameter set.
func (params MLDSAParameters) String() string { return params.name }

var errInvalidMLDSAParameters = errors.New("mldsa: invalid parameters")

// PrivateKeyMLDSA is an ML-DSA private key seed.
type PrivateKeyMLDSA struct {
	params MLDSAParameters
	seed   [privateKeySizeMLDSA]byte
}

// GenerateKeyMLDSA generates a new ML-DSA private key.
func GenerateKeyMLDSA(params MLDSAParameters) (*PrivateKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	key := &PrivateKeyMLDSA{params: params}
	if err := generateMLDSASeed(params.keyType, key.seed[:]); err != nil {
		return nil, err
	}
	return key, nil
}

// NewPrivateKeyMLDSA constructs an ML-DSA private key from its 32-byte seed.
func NewPrivateKeyMLDSA(params MLDSAParameters, seed []byte) (*PrivateKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	if len(seed) != privateKeySizeMLDSA {
		return nil, errors.New("mldsa: invalid private key size")
	}
	key := &PrivateKeyMLDSA{params: params}
	copy(key.seed[:], seed)
	return key, nil
}

// Bytes returns the private key seed.
func (key *PrivateKeyMLDSA) Bytes() []byte {
	return key.seed[:]
}

// Parameters returns the parameters associated with this private key.
func (key *PrivateKeyMLDSA) Parameters() MLDSAParameters { return key.params }

// PublicKey returns the corresponding public key.
func (key *PrivateKeyMLDSA) PublicKey() *PublicKeyMLDSA {
	publicKey := &PublicKeyMLDSA{params: key.params}
	if err := mldsaExtractPublicKey(key.params, key.seed[:], publicKey.bytes[:key.params.publicKeySize]); err != nil {
		panic(err)
	}
	return publicKey
}

// Sign signs message with the private key, optionally binding the signature
// to a context string. The context string must be at most 255 bytes long.
func (key *PrivateKeyMLDSA) Sign(message []byte, context string) ([]byte, error) {
	return mldsaSign(key.params, key.seed[:], message, context)
}

// SignExternalMu signs a pre-hashed mu message representative using ML-DSA.
// mu must be exactly 64 bytes long.
func (key *PrivateKeyMLDSA) SignExternalMu(mu []byte) ([]byte, error) {
	if len(mu) != muSizeMLDSA {
		return nil, errors.New("mldsa: invalid message hash length")
	}
	return mldsaSignExternalMu(key.params, key.seed[:], mu)
}

// PublicKeyMLDSA is an ML-DSA public key.
type PublicKeyMLDSA struct {
	params MLDSAParameters
	bytes  [publicKeySizeMLDSA87]byte
}

// NewPublicKeyMLDSA constructs an ML-DSA public key from its encoding.
func NewPublicKeyMLDSA(params MLDSAParameters, publicKey []byte) (*PublicKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	if len(publicKey) != params.publicKeySize {
		return nil, errors.New("mldsa: invalid public key size")
	}
	// Validate by attempting a key import.
	pkey, err := createMLDSAPublicKey(params.keyType, publicKey)
	if err != nil {
		return nil, err
	}
	ossl.EVP_PKEY_free(pkey)
	key := &PublicKeyMLDSA{params: params}
	copy(key.bytes[:], publicKey)
	return key, nil
}

// Bytes returns the public key encoding.
func (key *PublicKeyMLDSA) Bytes() []byte {
	return key.bytes[:key.params.publicKeySize]
}

// Parameters returns the parameters associated with this public key.
func (key *PublicKeyMLDSA) Parameters() MLDSAParameters { return key.params }

// Verify verifies an ML-DSA signature over message bound to the given context.
func (key *PublicKeyMLDSA) Verify(message, signature []byte, context string) error {
	return mldsaVerify(key.params, key.bytes[:key.params.publicKeySize], message, signature, context)
}

// VerifyExternalMu verifies an ML-DSA signature over a pre-hashed mu message
// representative. mu must be exactly 64 bytes long.
func (key *PublicKeyMLDSA) VerifyExternalMu(mu, signature []byte) error {
	if len(mu) != muSizeMLDSA {
		return errors.New("mldsa: invalid message hash length")
	}
	return mldsaVerifyExternalMu(key.params, key.bytes[:key.params.publicKeySize], mu, signature)
}

// Helper functions

// generateMLDSASeed generates a new ML-DSA private key and extracts the seed.
func generateMLDSASeed(keyType int32, seed []byte) error {
	pkey, err := generateEVPPKey(keyType, 0, "")
	if err != nil {
		return err
	}
	defer ossl.EVP_PKEY_free(pkey)

	_, err = ossl.EVP_PKEY_get_octet_string_param(pkey, _OSSL_PKEY_PARAM_ML_DSA_SEED.ptr(), seed, nil)
	return err
}

// createMLDSAPrivateKey creates an ML-DSA EVP_PKEY from a 32-byte seed.
func createMLDSAPrivateKey(id int32, seed []byte) (ossl.EVP_PKEY_PTR, error) {
	if len(seed) != privateKeySizeMLDSA {
		return nil, errors.New("mldsa: invalid seed size")
	}

	bld := newParamBuilder()
	defer bld.finalize()

	bld.addOctetString(_OSSL_PKEY_PARAM_ML_DSA_SEED, seed)

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)

	return newEvpFromParams(id, ossl.EVP_PKEY_KEYPAIR, params)
}

// createMLDSAPublicKey creates an ML-DSA EVP_PKEY from encoded public key bytes.
func createMLDSAPublicKey(id int32, pubKeyBytes []byte) (ossl.EVP_PKEY_PTR, error) {
	bld := newParamBuilder()
	defer bld.finalize()

	bld.addOctetString(_OSSL_PKEY_PARAM_PUB_KEY, pubKeyBytes)

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)

	return newEvpFromParams(id, ossl.EVP_PKEY_PUBLIC_KEY, params)
}

// mldsaExtractPublicKey derives and copies the encoded public key bytes from
// a private key seed.
func mldsaExtractPublicKey(params MLDSAParameters, seed, dst []byte) error {
	pkey, err := createMLDSAPrivateKey(params.keyType, seed)
	if err != nil {
		return err
	}
	defer ossl.EVP_PKEY_free(pkey)

	var pubLen int
	if _, err := ossl.EVP_PKEY_get_octet_string_param(pkey, _OSSL_PKEY_PARAM_PUB_KEY.ptr(), dst, &pubLen); err != nil {
		return err
	}
	if pubLen != params.publicKeySize {
		return errors.New("mldsa: unexpected public key size")
	}
	return nil
}

// mldsaSigParams builds the OSSL_PARAM array used to bind a context string
// (and/or the external-mu flag) to an ML-DSA Sign or Verify operation.
// Returns nil params when neither is set.
func mldsaSigParams(context string, externalMu bool) (ossl.OSSL_PARAM_PTR, error) {
	if len(context) > maxContextSizeMLDSA {
		return nil, errors.New("mldsa: context too long")
	}
	if context == "" && !externalMu {
		return nil, nil
	}
	bld := newParamBuilder()
	defer bld.finalize()
	if context != "" {
		bld.addOctetString(_OSSL_SIGNATURE_PARAM_CONTEXT_STRING, []byte(context))
	}
	if externalMu {
		bld.addInt32(_OSSL_SIGNATURE_PARAM_MU, 1)
	}
	return bld.build()
}

func mldsaSign(params MLDSAParameters, seed, message []byte, context string) ([]byte, error) {
	pkey, err := createMLDSAPrivateKey(params.keyType, seed)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_PKEY_free(pkey)

	return mldsaSignWithKey(pkey, params, message, context, false)
}

func mldsaSignExternalMu(params MLDSAParameters, seed, mu []byte) ([]byte, error) {
	pkey, err := createMLDSAPrivateKey(params.keyType, seed)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_PKEY_free(pkey)

	return mldsaSignWithKey(pkey, params, mu, "", true)
}

func mldsaSignWithKey(pkey ossl.EVP_PKEY_PTR, params MLDSAParameters, message []byte, context string, externalMu bool) ([]byte, error) {
	mdctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_MD_CTX_free(mdctx)

	var pctx ossl.EVP_PKEY_CTX_PTR
	if _, err := ossl.EVP_DigestSignInit(mdctx, &pctx, nil, nil, pkey); err != nil {
		return nil, err
	}
	sigParams, err := mldsaSigParams(context, externalMu)
	if err != nil {
		return nil, err
	}
	if sigParams != nil {
		defer ossl.OSSL_PARAM_free(sigParams)
		if _, err := ossl.EVP_PKEY_CTX_set_params(pctx, sigParams); err != nil {
			return nil, err
		}
	}

	signature := make([]byte, params.signatureSize)
	siglen := params.signatureSize
	if _, err := ossl.EVP_DigestSign(mdctx, signature, &siglen, message); err != nil {
		return nil, err
	}
	if siglen != params.signatureSize {
		return nil, errors.New("mldsa: unexpected signature length")
	}
	return signature[:siglen], nil
}

func mldsaVerify(params MLDSAParameters, publicKey, message, signature []byte, context string) error {
	if len(signature) != params.signatureSize {
		return errors.New("mldsa: invalid signature length")
	}
	pkey, err := createMLDSAPublicKey(params.keyType, publicKey)
	if err != nil {
		return err
	}
	defer ossl.EVP_PKEY_free(pkey)

	return mldsaVerifyWithKey(pkey, message, signature, context, false)
}

func mldsaVerifyExternalMu(params MLDSAParameters, publicKey, mu, signature []byte) error {
	if len(signature) != params.signatureSize {
		return errors.New("mldsa: invalid signature length")
	}
	pkey, err := createMLDSAPublicKey(params.keyType, publicKey)
	if err != nil {
		return err
	}
	defer ossl.EVP_PKEY_free(pkey)

	return mldsaVerifyWithKey(pkey, mu, signature, "", true)
}

func mldsaVerifyWithKey(pkey ossl.EVP_PKEY_PTR, message, signature []byte, context string, externalMu bool) error {
	mdctx, err := ossl.EVP_MD_CTX_new()
	if err != nil {
		return err
	}
	defer ossl.EVP_MD_CTX_free(mdctx)

	var pctx ossl.EVP_PKEY_CTX_PTR
	if _, err := ossl.EVP_DigestVerifyInit(mdctx, &pctx, nil, nil, pkey); err != nil {
		return err
	}
	sigParams, err := mldsaSigParams(context, externalMu)
	if err != nil {
		return err
	}
	if sigParams != nil {
		defer ossl.OSSL_PARAM_free(sigParams)
		if _, err := ossl.EVP_PKEY_CTX_set_params(pctx, sigParams); err != nil {
			return err
		}
	}

	if _, err := ossl.EVP_DigestVerify(mdctx, signature, message); err != nil {
		return errors.New("mldsa: invalid signature")
	}
	return nil
}
