//go:build !cmd_go_bootstrap

package openssl

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/golang-fips/openssl/v2/internal/ossl"
)

const (
	// sharedKeySizeMLKEM is the size of a shared key produced by ML-KEM.
	sharedKeySizeMLKEM = 32

	// seedSizeMLKEM is the size of a seed used to generate a decapsulation key.
	seedSizeMLKEM = 64

	// ciphertextSizeMLKEM768 is the size of a ciphertext produced by ML-KEM-768.
	ciphertextSizeMLKEM768 = 1088

	// encapsulationKeySizeMLKEM768 is the size of an ML-KEM-768 encapsulation key.
	encapsulationKeySizeMLKEM768 = 1184

	// ciphertextSizeMLKEM1024 is the size of a ciphertext produced by ML-KEM-1024.
	ciphertextSizeMLKEM1024 = 1568

	// encapsulationKeySizeMLKEM1024 is the size of an ML-KEM-1024 encapsulation key.
	encapsulationKeySizeMLKEM1024 = 1568
)

// SupportsMLKEM768 returns true if ML-KEM-768 is supported on this platform.
func SupportsMLKEM768() bool {
	if major() >= 3 && minor() >= 5 {
		return supportsMLKEM768()
	}
	return false
}

// SupportsMLKEM1024 returns true if ML-KEM-1024 is supported on this platform.
func SupportsMLKEM1024() bool {
	if major() >= 3 && minor() >= 5 {
		return supportsMLKEM1024()
	}
	return false
}

var supportsMLKEM768 = sync.OnceValue(func() bool {
	sig, _ := ossl.EVP_KEYMGMT_fetch(nil, _KeyTypeMLKEM768.ptr(), nil)
	if sig != nil {
		ossl.EVP_KEYMGMT_free(sig)
		return true
	}
	return false
})

var supportsMLKEM1024 = sync.OnceValue(func() bool {
	sig, _ := ossl.EVP_KEYMGMT_fetch(nil, _KeyTypeMLKEM1024.ptr(), nil)
	if sig != nil {
		ossl.EVP_KEYMGMT_free(sig)
		return true
	}
	return false
})

// DecapsulationKeyMLKEM768 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM768 [seedSizeMLKEM]byte

// GenerateKeyMLKEM768 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	var dk DecapsulationKeyMLKEM768
	if err := generateMLKEMSeed(ossl.EVP_PKEY_MLKEM_768, dk[:]); err != nil {
		return DecapsulationKeyMLKEM768{}, err
	}
	return dk, nil
}

// NewDecapsulationKeyMLKEM768 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	if len(seed) != seedSizeMLKEM {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: invalid seed size")
	}

	var dk DecapsulationKeyMLKEM768
	copy(dk[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Bytes() []byte {
	return dk[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	return performDecapsulation(ossl.NID_ML_KEM_768, dk[:], ciphertext)
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk DecapsulationKeyMLKEM768) EncapsulationKey() EncapsulationKeyMLKEM768 {
	ekBytes := extractEncapsulationKeyBytes(ossl.NID_ML_KEM_768, dk[:], encapsulationKeySizeMLKEM768)
	var ek EncapsulationKeyMLKEM768
	copy(ek[:], ekBytes)
	return ek
}

// An EncapsulationKeyMLKEM768 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM768.
type EncapsulationKeyMLKEM768 [encapsulationKeySizeMLKEM768]byte

// NewEncapsulationKeyMLKEM768 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM768 returns an error.
func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM768 {
		return EncapsulationKeyMLKEM768{}, errors.New("mlkem: invalid encapsulation key size")
	}

	var ek EncapsulationKeyMLKEM768
	copy(ek[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM768) Bytes() []byte {
	return ek[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM768) Encapsulate() (sharedKey, ciphertext []byte) {
	return performEncapsulation(ossl.NID_ML_KEM_768, ciphertextSizeMLKEM768, ek[:])
}

func performEncapsulation(id int32, ciphertextSize int, ek []byte) (sharedKey, ciphertext []byte) {
	pkey, err := createMLKEMPublicKey(id, ek)
	if err != nil {
		panic(err)
	}
	defer ossl.EVP_PKEY_free(pkey)

	// Create encapsulation context
	ctx, err := ossl.EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
	if err != nil {
		panic(err)
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)

	// Initialize encapsulation
	if _, err := ossl.EVP_PKEY_encapsulate_init(ctx, nil); err != nil {
		panic(err)
	}

	// Perform encapsulation - allocate buffers based on the key size
	sharedKey = make([]byte, sharedKeySizeMLKEM)
	ciphertext = make([]byte, ciphertextSize)

	sharedKeyLen := len(sharedKey)
	ciphertextLen := len(ciphertext)

	if _, err := ossl.EVP_PKEY_encapsulate(ctx, base(ciphertext), &ciphertextLen, base(sharedKey), &sharedKeyLen); err != nil {
		panic(err)
	}

	return sharedKey[:sharedKeyLen], ciphertext[:ciphertextLen]
}

func performDecapsulation(id int32, seed, ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	pkey, err := createMLKEMPrivateKey(id, seed)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_PKEY_free(pkey)

	// Create decapsulation context
	ctx, err := ossl.EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
	if err != nil {
		return nil, err
	}
	defer ossl.EVP_PKEY_CTX_free(ctx)

	// Initialize decapsulation
	if _, err := ossl.EVP_PKEY_decapsulate_init(ctx, nil); err != nil {
		return nil, err
	}

	// Perform decapsulation
	sharedKey = make([]byte, sharedKeySizeMLKEM)
	sharedKeyLen := len(sharedKey)
	if _, err := ossl.EVP_PKEY_decapsulate(ctx, base(sharedKey), &sharedKeyLen, base(ciphertext), len(ciphertext)); err != nil {
		return nil, err
	}

	return sharedKey[:sharedKeyLen], nil
}

// DecapsulationKeyMLKEM1024 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM1024 [seedSizeMLKEM]byte

// GenerateKeyMLKEM1024 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	var dk DecapsulationKeyMLKEM1024
	if err := generateMLKEMSeed(ossl.EVP_PKEY_MLKEM_1024, dk[:]); err != nil {
		return DecapsulationKeyMLKEM1024{}, err
	}
	return dk, nil
}

// NewDecapsulationKeyMLKEM1024 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	if len(seed) != seedSizeMLKEM {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid seed size")
	}

	var dk DecapsulationKeyMLKEM1024
	copy(dk[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Bytes() []byte {
	return dk[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	return performDecapsulation(ossl.NID_ML_KEM_1024, dk[:], ciphertext)
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk DecapsulationKeyMLKEM1024) EncapsulationKey() EncapsulationKeyMLKEM1024 {
	ekBytes := extractEncapsulationKeyBytes(ossl.NID_ML_KEM_1024, dk[:], encapsulationKeySizeMLKEM1024)
	var ek EncapsulationKeyMLKEM1024
	copy(ek[:], ekBytes)
	return ek
}

// An EncapsulationKeyMLKEM1024 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM1024.
type EncapsulationKeyMLKEM1024 [encapsulationKeySizeMLKEM1024]byte

// NewEncapsulationKeyMLKEM1024 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM1024 returns an error.
func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM1024 {
		return EncapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid encapsulation key size")
	}

	var ek EncapsulationKeyMLKEM1024
	copy(ek[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM1024) Bytes() []byte {
	return ek[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM1024) Encapsulate() (sharedKey, ciphertext []byte) {
	return performEncapsulation(ossl.NID_ML_KEM_1024, ciphertextSizeMLKEM1024, ek[:])
}

// Helper functions

// generateMLKEMSeed generates a new ML-KEM seed by creating a key and extracting its seed parameter.
func generateMLKEMSeed(keyType int32, seed []byte) error {
	pkey, err := generateEVPPKey(keyType, 0, "")
	if err != nil {
		return err
	}
	defer ossl.EVP_PKEY_free(pkey)

	_, err = ossl.EVP_PKEY_get_octet_string_param(pkey, _OSSL_PKEY_PARAM_ML_KEM_SEED.ptr(), seed, nil)
	return err
}

// createMLKEMPrivateKey creates an ML-KEM private key from a seed
func createMLKEMPrivateKey(id int32, seed []byte) (ossl.EVP_PKEY_PTR, error) {
	if len(seed) != seedSizeMLKEM {
		return nil, errors.New("mlkem: invalid seed size")
	}

	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()

	bld.addOctetString(_OSSL_PKEY_PARAM_ML_KEM_SEED, seed)

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)

	return newEvpFromParams(id, ossl.EVP_PKEY_KEYPAIR, params)
}

// createMLKEMPublicKey creates an ML-KEM public key from encoded bytes.
func createMLKEMPublicKey(id int32, pubKeyBytes []byte) (ossl.EVP_PKEY_PTR, error) {
	bld, err := newParamBuilder()
	if err != nil {
		return nil, err
	}
	defer bld.finalize()

	bld.addOctetString(_OSSL_PKEY_PARAM_PUB_KEY, pubKeyBytes)

	params, err := bld.build()
	if err != nil {
		return nil, err
	}
	defer ossl.OSSL_PARAM_free(params)

	return newEvpFromParams(id, ossl.EVP_PKEY_PUBLIC_KEY, params)
}

// extractEncapsulationKeyBytes extracts the encapsulation key bytes from a decapsulation key.
func extractEncapsulationKeyBytes(id int32, seed []byte, expectedSize int) []byte {
	pkey, err := createMLKEMPrivateKey(id, seed)
	if err != nil {
		panic(err)
	}
	defer ossl.EVP_PKEY_free(pkey)

	// Extract public key bytes
	var pubBytes *byte
	pubLen, err := ossl.EVP_PKEY_get1_encoded_public_key(pkey, &pubBytes)
	if err != nil {
		panic(err)
	}
	defer cryptoFree(unsafe.Pointer(pubBytes))

	if pubLen != expectedSize {
		panic(errors.New("mlkem: invalid encapsulation key size"))
	}

	// Copy the bytes before pubBytes is freed
	result := make([]byte, pubLen)
	copy(result, unsafe.Slice(pubBytes, pubLen))
	return result
}
