package openssl

import "sync"

var ErrOpen = errOpen

var SymCryptProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("symcryptprovider\x00")
})

var FIPSProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("fips\x00")
})

var DefaultProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("default\x00")
})
