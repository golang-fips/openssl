//go:build noopt

package openssl_test

// OptimizationOff reports whether optimization is disabled.
func OptimizationOff() bool {
	return true
}
