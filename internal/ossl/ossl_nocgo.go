//go:build !cgo && goexperiment.ms_nocgo_opensslcrypto

package ossl

import "unsafe"

// HashSum copies ctx1 into ctx2 and calls EVP_DigestFinal_ex using ctx2.
// This is necessary because Go hash.Hash mandates that Sum has no effect
// on the underlying stream. In particular it is OK to Sum, then Write more,
// then Sum again, and the second Sum acts as if the first didn't happen.
func HashSum(ctx1, ctx2 EVP_MD_CTX_PTR, out []byte) error {
	// Copy ctx1 to ctx2 using EVP_MD_CTX_copy_ex
	code, err := EVP_MD_CTX_copy_ex(ctx2, ctx1)
	if err != nil {
		return err
	}
	var errState uintptr
	if code != 1 {
		errState = retrieveErrorState()
		return newMkcgoErr("EVP_MD_CTX_copy_ex", errState)
	}

	// Finalize the hash using ctx2
	code, err = EVP_DigestFinal_ex(ctx2, (*byte)(unsafe.SliceData(out)), nil)
	if err != nil {
		return err
	}
	if code <= 0 {
		errState = retrieveErrorState()
		return newMkcgoErr("EVP_DigestFinal_ex", errState)
	}

	return nil
}
