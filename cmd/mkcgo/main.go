package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"slices"
	"strings"
)

var (
	fileName      = flag.String("out", "", "output file name (standard output if omitted)")
	includeHeader = flag.String("include", "", "include header file")
	packageName   = flag.String("package", "", "package name")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: mkcgo [flags] [path ...]\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nsupported function attributes:\n")
	for _, attr := range attributes {
		fmt.Fprintf(os.Stderr, "  %s: %s\n", attr.name, attr.description)
	}
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}

func main() {
	// Set up and parse flags.
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "no files to parse provided")
		usage()
	}

	// Parse source files.
	src, err := parseFiles(flag.Args())
	if err != nil {
		log.Fatal(err)
	}

	var buf, cbuf bytes.Buffer
	src.generateGo(&buf)
	src.generateC(&cbuf)

	// Format the generated Go source code.
	data, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("failed to format source: %v", err)
		f, err := writeTempSourceFile(buf.Bytes())
		if err != nil {
			log.Fatalf("failed to write unformatted source to file: %v", err)
		}
		log.Fatalf("for diagnosis, wrote unformatted source to %v", f)
	}

	// Write output. If no explicit output file is specified,
	// // write both Go and C output to stdout.
	if *fileName == "" {
		for _, d := range [][]byte{data, cbuf.Bytes()} {
			if _, err = os.Stdout.Write(d); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		err = os.WriteFile(*fileName, data, 0o644)
		if err == nil {
			cfileName := strings.TrimSuffix(*fileName, ".go") + ".c"
			err = os.WriteFile(cfileName, cbuf.Bytes(), 0o644)
		}
		if err != nil {
			log.Fatal(err)
		}
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
	name string
	typ  string
}

type fnAttributes struct {
	tag        string
	variadic   bool
	importName string
}

// fn describes a function.
type fn struct {
	goName     string
	cName      string
	importName string
	tag        string
	params     []*param
	rets       *rets
	src        string
	variadic   bool
}

type source struct {
	funcs         []*fn
	stdLibImports []string
	files         []string
	ctypes        map[string]struct{}
}

func (src *source) tags() []string {
	var tags []string
	for _, fn := range src.funcs {
		if !slices.Contains(tags, fn.tag) {
			tags = append(tags, fn.tag)
		}
	}
	slices.Sort(tags)
	return tags
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
