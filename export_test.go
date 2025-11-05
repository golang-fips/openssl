package openssl

import "sync"

var ErrOpen = errOpen

var SymCryptProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("symcryptprovider")
})

var FIPSProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("fips")
})

var DefaultProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("default")
})

// MLKEM constants for testing against the stdlib
var (
	SharedKeySizeMLKEM            = sharedKeySizeMLKEM
	SeedSizeMLKEM                 = seedSizeMLKEM
	CiphertextSizeMLKEM768        = ciphertextSizeMLKEM768
	EncapsulationKeySizeMLKEM768  = encapsulationKeySizeMLKEM768
	CiphertextSizeMLKEM1024       = ciphertextSizeMLKEM1024
	EncapsulationKeySizeMLKEM1024 = encapsulationKeySizeMLKEM1024
)

var HashBufSize = hashBufSize
