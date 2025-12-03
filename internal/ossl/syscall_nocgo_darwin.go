//go:build !cgo && darwin && goexperiment.ms_nocgo_opensslcrypto

package ossl

//go:cgo_import_dynamic _ _ "/usr/lib/libSystem.B.dylib"
