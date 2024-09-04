package openssl

import "sync"

var ErrOpen = errOpen

var SymCryptProviderAvailable = sync.OnceValue(func() bool {
	if vMajor == 1 {
		return false
	}
	return isProviderAvailable("symcryptprovider")
})
