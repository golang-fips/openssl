package openssl

var ErrOpen = errOpen

// MLKEM constants for testing against the stdlib
var (
	SharedKeySizeMLKEM            = sharedKeySizeMLKEM
	SeedSizeMLKEM                 = seedSizeMLKEM
	CiphertextSizeMLKEM768        = ciphertextSizeMLKEM768
	EncapsulationKeySizeMLKEM768  = encapsulationKeySizeMLKEM768
	CiphertextSizeMLKEM1024       = ciphertextSizeMLKEM1024
	EncapsulationKeySizeMLKEM1024 = encapsulationKeySizeMLKEM1024
)

// MLDSA constants for testing against the stdlib
var (
	PrivateKeySizeMLDSA  = privateKeySizeMLDSA
	PublicKeySizeMLDSA44 = publicKeySizeMLDSA44
	PublicKeySizeMLDSA65 = publicKeySizeMLDSA65
	PublicKeySizeMLDSA87 = publicKeySizeMLDSA87
	SignatureSizeMLDSA44 = signatureSizeMLDSA44
	SignatureSizeMLDSA65 = signatureSizeMLDSA65
	SignatureSizeMLDSA87 = signatureSizeMLDSA87
)

var HashBufSize = hashBufSize
