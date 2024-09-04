package openssl

import "sync"

var ErrOpen = errOpen

var SymCryptProviderAvailable = sync.OnceValue(func() bool {
	return isProviderAvailable("symcryptprovider")
})
