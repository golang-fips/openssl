//go:build !cmd_go_bootstrap

package openssl

import (
	"hash"
)

type HashCloner = hash.Cloner
