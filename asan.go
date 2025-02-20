//go:build asan && !cmd_go_bootstrap

package openssl

// -fsanitize=leak instructs the compiler and linker to use the leak sanitizer
// and report memory leaks on exit.

// #cgo CFLAGS: -fsanitize=leak
// #cgo LDFLAGS: -fsanitize=leak
import "C"