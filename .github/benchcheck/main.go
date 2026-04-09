// benchcheck is a tool for analyzing Go benchmark results in CI.
//
// Commands:
//
//	benchcheck check [flags] base.txt head.txt
//	benchcheck report [flags] results-dir
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: benchcheck <command> [flags] [args]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  check   Compare benchmarks, detect regressions and test failures\n")
	fmt.Fprintf(os.Stderr, "  report  Build a markdown report from benchmark artifacts\n")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "check":
		cmdCheck(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "-h", "-help", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
	}
}
