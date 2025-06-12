//go:build !cmd_go_bootstrap

package openssl

import (
	"hash"
)

// HashCloner is an interface that defines a Clone method.
type HashCloner interface {
	hash.Hash
	// Clone returns a separate Hash instance with the same state as h.
	Clone() (HashCloner, error)
}
