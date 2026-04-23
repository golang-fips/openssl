//go:build !cmd_go_bootstrap && !go1.26

package openssl

func fips140Enforced() bool {
	return true
}
