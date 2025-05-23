//go:build !cmd_go_bootstrap

package openssl

// #include "goopenssl.h"
import "C"
import (
	"crypto"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// This file contains code specific to the SymCrypt provider.

var (
	_SCOSSL_DIGEST_PARAM_STATE              = C.CString("state")
	_SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM = C.CString("recompute_checksum")
)

const (
	_SYMCRYPT_BLOB_MAGIC = 0x636D7973 // "cysm" in little-endian

	_SymCryptBlobTypeHashState       = 0x100
	_SymCryptBlobTypeMd2State        = _SymCryptBlobTypeHashState + 1
	_SymCryptBlobTypeMd4State        = _SymCryptBlobTypeHashState + 2
	_SymCryptBlobTypeMd5State        = _SymCryptBlobTypeHashState + 3
	_SymCryptBlobTypeSha1State       = _SymCryptBlobTypeHashState + 4
	_SymCryptBlobTypeSha256State     = _SymCryptBlobTypeHashState + 5
	_SymCryptBlobTypeSha384State     = _SymCryptBlobTypeHashState + 6
	_SymCryptBlobTypeSha512State     = _SymCryptBlobTypeHashState + 7
	_SymCryptBlobTypeSha3_256State   = _SymCryptBlobTypeHashState + 8
	_SymCryptBlobTypeSha3_384State   = _SymCryptBlobTypeHashState + 9
	_SymCryptBlobTypeSha3_512State   = _SymCryptBlobTypeHashState + 10
	_SymCryptBlobTypeSha224State     = _SymCryptBlobTypeHashState + 11
	_SymCryptBlobTypeSha512_224State = _SymCryptBlobTypeHashState + 12
	_SymCryptBlobTypeSha512_256State = _SymCryptBlobTypeHashState + 13
	_SymCryptBlobTypeSha3_224State   = _SymCryptBlobTypeHashState + 14

	_SYMCRYPT_MD5_STATE_EXPORT_SIZE    = uint32(unsafe.Sizeof(_SYMCRYPT_MD5_STATE_EXPORT_BLOB{}))
	_SYMCRYPT_SHA1_STATE_EXPORT_SIZE   = uint32(unsafe.Sizeof(_SYMCRYPT_SHA1_STATE_EXPORT_BLOB{}))
	_SYMCRYPT_SHA256_STATE_EXPORT_SIZE = uint32(unsafe.Sizeof(_SYMCRYPT_SHA256_STATE_EXPORT_BLOB{}))
	_SYMCRYPT_SHA512_STATE_EXPORT_SIZE = uint32(unsafe.Sizeof(_SYMCRYPT_SHA512_STATE_EXPORT_BLOB{}))
)

type _SYMCRYPT_BLOB_HEADER struct {
	magic uint32
	size  uint32
	_type uint32
}

type _SYMCRYPT_BLOB_TRAILER struct {
	checksum [8]uint8
}

// _UINT64 is a 64-bit unsigned integer, stored in native endianess.
// It is used to represent a SymCrypt UINT64 type without making the
// parent struct 8-byte aligned, given that the Windows ABI makes
// the struct 4-byte aligned.
type _UINT64 [2]uint32

func newUINT64(v uint64) _UINT64 {
	var u _UINT64
	if nativeEndian == binary.BigEndian {
		u[0], u[1] = uint32(v>>32), uint32(v)
	} else {
		u[0], u[1] = uint32(v), uint32(v>>32)
	}
	return u
}

func (u *_UINT64) uint64() uint64 {
	if nativeEndian == binary.BigEndian {
		return uint64(u[0])<<32 | (uint64(u[1]))
	}
	return uint64(u[0]) | (uint64(u[1]) << 32)
}

// symCryptAppendBinary appends the binary representation of a SymCrypt state
// to the given destination slice.
func symCryptAppendBinary(dst, chain, buffer []byte, blength _UINT64) []byte {
	length := blength.uint64()
	var nx uint64
	if len(buffer) <= 64 {
		nx = length & 0x3f
	} else {
		nx = length & 0x7f
	}
	dst = append(dst, chain...)
	dst = append(dst, buffer[:nx]...)
	dst = append(dst, make([]byte, len(buffer)-int(nx))...)
	dst = appendUint64(dst, length)
	return dst
}

// symCryptUnmarshalBinary unmarshals the binary representation of a SymCrypt state
// from the given source slice. It returns the length of the data.
func symCryptUnmarshalBinary(d []byte, chain, buffer []byte) _UINT64 {
	copy(chain[:], d)
	d = d[len(chain):]
	copy(buffer[:], d)
	d = d[len(buffer):]
	_, length := consumeUint64(d)
	return newUINT64(length)
}

// swapEndianessInt32 swaps the endianness of the given byte slice
// in place. It assumes the slice is a backup of a 32-bit integer array.
func swapEndianessInt32(d []uint8) {
	for i := 0; i < len(d); i += 4 {
		d[i], d[i+3] = d[i+3], d[i]
		d[i+1], d[i+2] = d[i+2], d[i+1]
	}

}

type _SYMCRYPT_MD5_STATE_EXPORT_BLOB struct {
	header _SYMCRYPT_BLOB_HEADER
	chain  [16]uint8 // little endian
	length _UINT64   // native endian
	buffer [64]uint8
	_      [8]uint8 // reserved
	_      _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_MD5_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	// b.chain is little endian, but Go expects big endian,
	// we need to swap the bytes.
	swapEndianessInt32(b.chain[:])
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.length), nil
}

func (b *_SYMCRYPT_MD5_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.length = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
	swapEndianessInt32(b.chain[:])
}

type _SYMCRYPT_SHA1_STATE_EXPORT_BLOB struct {
	header _SYMCRYPT_BLOB_HEADER
	chain  [20]uint8 // big endian
	length _UINT64   // native endian
	buffer [64]uint8
	_      [8]uint8 // reserved
	_      _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_SHA1_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.length), nil
}

func (b *_SYMCRYPT_SHA1_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.length = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
}

type _SYMCRYPT_SHA256_STATE_EXPORT_BLOB struct {
	header _SYMCRYPT_BLOB_HEADER
	chain  [32]uint8 // big endian
	length _UINT64   // native endian
	buffer [64]uint8
	_      [8]uint8 // reserved
	_      _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_SHA256_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.length), nil
}

func (b *_SYMCRYPT_SHA256_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.length = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
}

type _SYMCRYPT_SHA512_STATE_EXPORT_BLOB struct {
	header  _SYMCRYPT_BLOB_HEADER
	chain   [64]uint8 // big endian
	lengthL _UINT64   // native endian
	lengthH _UINT64   // native endian
	buffer  [128]uint8
	_       [8]uint8 // reserved
	_       _SYMCRYPT_BLOB_TRAILER
}

func (b *_SYMCRYPT_SHA512_STATE_EXPORT_BLOB) appendBinary(d []byte) ([]byte, error) {
	if b.lengthH.uint64() != 0 {
		return nil, errors.New("exporting state with more than 2^63-1 bytes of data is not supported")
	}
	return symCryptAppendBinary(d, b.chain[:], b.buffer[:], b.lengthL), nil
}

func (b *_SYMCRYPT_SHA512_STATE_EXPORT_BLOB) unmarshalBinary(d []byte) {
	b.lengthL = symCryptUnmarshalBinary(d, b.chain[:], b.buffer[:])
}

func symCryptHashAppendBinary(ctx C.GO_EVP_MD_CTX_PTR, ch crypto.Hash, magic string, buf []byte) ([]byte, error) {
	size, typ, serializable := symCryptHashStateInfo(ch)
	if !serializable {
		return nil, errHashNotMarshallable
	}
	state := make([]byte, size, _SYMCRYPT_SHA512_STATE_EXPORT_SIZE) // 512 is the largest size
	var pinner runtime.Pinner
	pinner.Pin(&state[0])
	defer pinner.Unpin()
	params := [2]_OSSL_PARAM{
		_OSSL_PARAM_construct_octet_string(_SCOSSL_DIGEST_PARAM_STATE, unsafe.Pointer(&state[0]), len(state)),
		_OSSL_PARAM_construct_end(),
	}
	if C.go_openssl_EVP_MD_CTX_get_params(ctx, (C.GO_OSSL_PARAM_PTR)(unsafe.Pointer(&params[0]))) != 1 {
		return nil, newOpenSSLError("EVP_MD_CTX_get_params")
	}

	header := (*_SYMCRYPT_BLOB_HEADER)(unsafe.Pointer(&state[0]))
	if header.magic != _SYMCRYPT_BLOB_MAGIC {
		return nil, errors.New("invalid blob magic")
	}
	if header.size != size {
		return nil, errors.New("invalid blob size")
	}
	if header._type != typ {
		return nil, errors.New("invalid blob type")
	}

	buf = append(buf, magic...)
	switch ch {
	case crypto.MD5:
		blob := (*_SYMCRYPT_MD5_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	case crypto.SHA1:
		blob := (*_SYMCRYPT_SHA1_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	case crypto.SHA224, crypto.SHA256:
		blob := (*_SYMCRYPT_SHA256_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		blob := (*_SYMCRYPT_SHA512_STATE_EXPORT_BLOB)(unsafe.Pointer(&state[0]))
		return blob.appendBinary(buf)
	default:
		panic("unsupported hash " + ch.String())
	}
}

func symCryptHashUnmarshalBinary(ctx C.GO_EVP_MD_CTX_PTR, ch crypto.Hash, magic string, b []byte) error {
	size, typ, serializable := symCryptHashStateInfo(ch)
	if !serializable {
		return errHashNotMarshallable
	}
	hdr := _SYMCRYPT_BLOB_HEADER{
		magic: _SYMCRYPT_BLOB_MAGIC,
		size:  size,
		_type: typ,
	}
	var blobPtr unsafe.Pointer
	b = b[len(magic):]
	switch ch {
	case crypto.MD5:
		var blob _SYMCRYPT_MD5_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	case crypto.SHA1:
		var blob _SYMCRYPT_SHA1_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	case crypto.SHA224, crypto.SHA256:
		var blob _SYMCRYPT_SHA256_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	case crypto.SHA384, crypto.SHA512_224, crypto.SHA512_256, crypto.SHA512:
		var blob _SYMCRYPT_SHA512_STATE_EXPORT_BLOB
		blobPtr = unsafe.Pointer(&blob)
		blob.header = hdr
		blob.unmarshalBinary(b)
	default:
		panic("unsupported hash " + ch.String())
	}
	bld := C.go_openssl_OSSL_PARAM_BLD_new()
	if bld == nil {
		return newOpenSSLError("OSSL_PARAM_BLD_new")
	}
	defer C.go_openssl_OSSL_PARAM_BLD_free(bld)
	cbytes := C.CBytes(unsafe.Slice((*byte)(blobPtr), hdr.size))
	defer C.free(cbytes)
	C.go_openssl_OSSL_PARAM_BLD_push_octet_string(bld, _SCOSSL_DIGEST_PARAM_STATE, cbytes, C.size_t(hdr.size))
	C.go_openssl_OSSL_PARAM_BLD_push_int32(bld, _SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM, 1)
	params := C.go_openssl_OSSL_PARAM_BLD_to_param(bld)
	if params == nil {
		return newOpenSSLError("OSSL_PARAM_BLD_to_param")
	}
	defer C.go_openssl_OSSL_PARAM_free(params)
	if C.go_openssl_EVP_MD_CTX_set_params(ctx, params) == 0 {
		return newOpenSSLError("EVP_MD_CTX_set_params")
	}
	return nil
}

func symCryptHashStateInfo(ch crypto.Hash) (size, typ uint32, serializable bool) {
	switch ch {
	case crypto.MD5:
		return _SYMCRYPT_MD5_STATE_EXPORT_SIZE, _SymCryptBlobTypeMd5State, symCryptHashStateSerializableMD5()
	case crypto.SHA1:
		return _SYMCRYPT_SHA1_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha1State, symCryptHashStateSerializableSHA1()
	case crypto.SHA224:
		return _SYMCRYPT_SHA256_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha224State, symCryptHashStateSerializableSHA224()
	case crypto.SHA256:
		return _SYMCRYPT_SHA256_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha256State, symCryptHashStateSerializableSHA256()
	case crypto.SHA384:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha384State, symCryptHashStateSerializableSHA384()
	case crypto.SHA512_224:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha512_224State, symCryptHashStateSerializableSHA512_224()
	case crypto.SHA512_256:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha512_256State, symCryptHashStateSerializableSHA512_256()
	case crypto.SHA512:
		return _SYMCRYPT_SHA512_STATE_EXPORT_SIZE, _SymCryptBlobTypeSha512State, symCryptHashStateSerializableSHA512()
	default:
		panic("unsupported hash " + ch.String())
	}
}

var (
	symCryptHashStateSerializableMD5 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.MD5)
	})
	symCryptHashStateSerializableSHA1 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.SHA1)
	})
	symCryptHashStateSerializableSHA224 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.SHA224)
	})
	symCryptHashStateSerializableSHA256 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.SHA256)
	})
	symCryptHashStateSerializableSHA384 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.SHA384)
	})
	symCryptHashStateSerializableSHA512_224 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.SHA512_224)
	})
	symCryptHashStateSerializableSHA512_256 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.SHA512_256)
	})
	symCryptHashStateSerializableSHA512 = sync.OnceValue(func() bool {
		return isSymCryptHashStateSerializable(crypto.SHA512)
	})
)

// isSymCryptHashStateSerializable checks if the SymCrypt hash state is serializable.
func isSymCryptHashStateSerializable(ch crypto.Hash) bool {
	md := cryptoHashToMD(ch)
	if md == nil {
		return false
	}
	ctx := C.go_openssl_EVP_MD_CTX_new()
	if ctx == nil {
		return false
	}
	defer C.go_openssl_EVP_MD_CTX_free(ctx)
	if C.go_openssl_EVP_DigestInit_ex(ctx, md, nil) != 1 {
		return false
	}
	params := C.go_openssl_EVP_MD_CTX_gettable_params(ctx)
	if params == nil {
		return false
	}
	if C.go_openssl_OSSL_PARAM_locate_const(params, _SCOSSL_DIGEST_PARAM_STATE) == nil {
		return false
	}
	params = C.go_openssl_EVP_MD_CTX_settable_params(ctx)
	if params == nil {
		return false
	}
	if C.go_openssl_OSSL_PARAM_locate_const(params, _SCOSSL_DIGEST_PARAM_STATE) == nil {
		return false
	}
	if C.go_openssl_OSSL_PARAM_locate_const(params, _SCOSSL_DIGEST_PARAM_RECOMPUTE_CHECKSUM) == nil {
		return false
	}
	return true
}
