//go:build !cgo && goexperiment.ms_nocgo_opensslcrypto

package ossl

// retrieveErrorState retrieves errors from the OpenSSL error queue.
// It might run on the system stack, so it can't allocate Go memory
// nor grow the stack over the nosplit limit.
//
//go:nosplit
func retrieveErrorState() uintptr {
	// BIO operations using BIO_s_mem should not fail.
	smem := syscallNRaw(_mkcgo_BIO_s_mem)
	bio := syscallNRaw(_mkcgo_BIO_new, smem)
	syscallNRaw(_mkcgo_ERR_print_errors, bio)
	return bio
}
