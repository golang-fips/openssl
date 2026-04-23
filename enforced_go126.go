//go:build !cmd_go_bootstrap && go1.26

package openssl

import "crypto/fips140"

var fips140Enforced = fips140.Enforced
