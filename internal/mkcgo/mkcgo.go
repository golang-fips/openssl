package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"strings"
)

var (
	defaultErrorCodeStr string
)

var (
	fileName      = flag.String("out", "", "output file name (standard output if omitted)")
	includeHeader = flag.String("include", "", "include header file")
	packageName   = flag.String("package", "", "package name")
	libName       = flag.String("lib", "", "library name")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: mkcgo [flags] [path ...]\n")
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) <= 0 {
		fmt.Fprintf(os.Stderr, "no files to parse provided\n")
		usage()
	}

	src, err := parseFiles(flag.Args())
	if err != nil {
		log.Fatal(err)
	}

	var buf, cbuf bytes.Buffer
	src.generate(&buf)
	src.generateC(&cbuf)

	data, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("failed to format source: %v", err)
		f, err := writeTempSourceFile(buf.Bytes())
		if err != nil {
			log.Fatalf("failed to write unformatted source to file: %v", err)
		}
		log.Fatalf("for diagnosis, wrote unformatted source to %v", f)
	}
	if *fileName == "" {
		_, err = os.Stdout.Write(data)
		if err == nil {
			_, err = os.Stdout.Write(cbuf.Bytes())
		}
	} else {
		err = os.WriteFile(*fileName, data, 0644)
		if err == nil {
			cfileName := strings.TrimSuffix(*fileName, ".go") + ".c"
			err = os.WriteFile(cfileName, cbuf.Bytes(), 0644)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}

// param is function parameter.
type param struct {
	name      string
	typ       string
	tmpVarIdx int
}

// isError determines if p parameter is used to return error.
func (p *param) isError() bool {
	return p.name == "err" && p.typ == "error"
}

// rets is function return values.
type rets struct {
	name          string
	typ           string
	returnsError  bool
	errorOnly     bool
	failCond      string
	errorType     string
	fnMaybeAbsent bool
}

type fnOptions struct {
	name          string
	libName       string
	errorType     string
	errorOnly     bool
	returnsError  bool
	failCondition string
	importName    string
	cOnly         bool
}

// fn describes a function.
type fn struct {
	name       string
	libName    string
	importName string
	params     []*param
	rets       *rets
	src        string
	isVariadic bool
	cOnly      bool
}

type source struct {
	funcs         []*fn
	stdLibImports []string
	files         []string
}

func writeTempSourceFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "mkcgo-generated-*.go")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name()) // best effort
		return "", err
	}
	return f.Name(), nil
}
