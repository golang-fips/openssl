package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/golang-fips/openssl/v2/internal/mkcgo"
)

// checkheader is a static analyzer that detects incompatibilities between wrapper definitions and OpenSSL headers.
// It generates a C source file where for each wrapper, the file declares a new symbol that's assigned to the symbol it represents in the actual OpenSSL headers.
// This C file is then compiled using GCC. The compilation will succeed if everything is compatible, else it will
// report a meaningful error.
//
// The C source file is generated based on only the wrappers header and these rules:
// - Lines are added in order of appearance.
// - Blank lines are discarded.
// - Comments are discarded unless they contain a C directive, i.e #include, #if or #endif. The directive in the comment is included in the output.
// - Typedefs following the pattern "typedef void* _%name%_PTR" are translated into "#define %name% _%name%_PTR".
// - Go constants are validated against their definition in the OpenSSL headers. Example:
//   "const { _EVP_CTRL_GCM_SET_TAG = 0x11 }" => "_Static_assert(EVP_CTRL_GCM_SET_TAG == 0x11);"
// - Function macros are validated against their definition in the OpenSSL headers. Example:
//   "int RAND_bytes(unsigned char *a0, int a1)" => "int(*__check_0)(unsigned char *, int) = RAND_bytes;"

const description = `
Example: A check operation:
  go run ./cmd/checkheader --ossl-include /usr/local/src/openssl-1.1.1/include -shim ./shims.h 
Checkheader generates a C program and compiles it with gcc. The compilation verifies types and functions defined in the target
header file match the definitions in --ossl-include.
`

var osslInclude = flag.String("ossl-include", "", "OpenSSL include directory. Required.")
var osslShim = flag.String("shim", "", "C header containing the OpenSSL wrappers. Required.")
var work = flag.Bool("work", false, "print the name of the temporary C program file and do not delete it when exiting.")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "\nUsage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\n", description)
	}
	flag.Parse()
	if *osslInclude == "" {
		fmt.Fprintln(flag.CommandLine.Output(), "required flag not provided: --ossl-include")
		flag.Usage()
		os.Exit(1)
	}
	if *osslShim == "" {
		fmt.Fprintln(flag.CommandLine.Output(), "required flag not provided: -shim")
		flag.Usage()
		os.Exit(1)
	}
	if _, err := os.Stat(*osslInclude); err != nil {
		log.Fatalf("OpenSSL include directory not found: %v\n", err)
	}
	s, err := generate(*osslShim)
	if err != nil {
		log.Fatal(err)
	}
	err = gccRun(s)
	if err != nil {
		log.Fatal(err)
	}
}

func gccRun(program string) error {
	f, err := os.CreateTemp("", "go-crypto-openssl-*.c")
	if err != nil {
		log.Fatal(err)
	}
	name := f.Name()
	if !*work {
		defer os.Remove(name)
	} else {
		defer log.Println(name)
	}
	if _, err = f.WriteString(program); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	// gcc will fail to compile the generated C header if
	// any of the static checks fail. If it succeeds, it means
	// the checked header matches the OpenSSL definitions.
	p := exec.Command("gcc",
		"-c",                      // skip linking
		"-Werror",                 // promote all warnings to errors
		"-DOPENSSL_NO_DEPRECATED", // hide deprecated functions
		"-isystem", *osslInclude,  // OpenSSL include from --ossl-include must be preferred over system includes
		"-o", os.DevNull, // discard output
		name)
	p.Stdout = os.Stdout
	p.Stderr = os.Stderr
	return p.Run()
}

func generate(header string) (string, error) {
	src, err := mkcgo.Parse(header)
	if err != nil {
		return "", err
	}
	w := &strings.Builder{}

	for _, c := range src.Comments {
		if strings.HasPrefix(c, "#") {
			fmt.Fprintln(w, c)
		}
	}

	for _, enum := range src.Enums {
		if enum.Name == "_EVP_PKEY_OP_DERIVE" {
			// This is defined differently in OpenSSL 3,
			// but in our code it is only used in OpenSSL 1.
			continue
		}
		name := strings.TrimPrefix(enum.Name, "_")
		fmt.Fprintf(w, "#ifdef %s\n", name)
		fmt.Fprintf(w, "_Static_assert(%s == %s, \"%s\");\n", enum.Value, name, enum.Name)
		fmt.Fprintln(w, "#endif")
	}

	for _, def := range src.TypeDefs {
		name := strings.TrimPrefix(def.Name, "_")
		name = strings.Replace(name, "_PTR", "*", 1)
		fmt.Fprintf(w, "#define %s %s\n", def.Name, name)
	}
	var i int
	writeDefineFunc := func(tagCond string, importName string, params []*mkcgo.Param, ret *mkcgo.Return) {
		var specialCond string
		switch importName {
		// EVP_PKEY_size and EVP_PKEY_bits pkey parameter is const since OpenSSL 1.1.1.
		case "EVP_PKEY_size", "EVP_PKEY_bits":
			specialCond = "OPENSSL_VERSION_NUMBER >= 0x10101000L"
		}
		if specialCond != "" {
			fmt.Fprintf(w, "#if %s\n", specialCond)
		}
		if tagCond != "" {
			fmt.Fprintf(w, "#if %s\n", tagCond)
		}
		sparams := make([]string, 0, len(params))
		for _, p := range params {
			sparams = append(sparams, p.Type)
		}
		fmt.Fprintf(w, "%s (*__check_%d)(%s) = %s;\n", ret.Type, i, strings.Join(sparams, ", "), importName)
		if tagCond != "" {
			fmt.Fprintln(w, "#endif")
		}
		if specialCond != "" {
			fmt.Fprintln(w, "#endif")
		}
		i++
	}

	for _, fn := range src.Funcs {
		if fn.VariadicInst {
			// Variadic instantiations are not real OpenSSL functions,
			// skip them.
			continue
		}
		if len(fn.Tags) == 0 {
			writeDefineFunc("", fn.ImportName, fn.Params, fn.Ret)
			continue
		}
		for _, tag := range fn.Tags {
			var tagCond string
			switch tag.Tag {
			case "legacy_1":
				tagCond = "OPENSSL_VERSION_NUMBER < 0x30000000L"
			case "111":
				tagCond = "OPENSSL_VERSION_NUMBER >= 0x10101000L"
			case "3":
				tagCond = "OPENSSL_VERSION_NUMBER >= 0x30000000L"
			default:
				panic("unexpected tag: " + tag.Tag)
			}
			importName := fn.ImportName
			if tag.Name != "" {
				importName = tag.Name
			}
			writeDefineFunc(tagCond, importName, fn.Params, fn.Ret)
		}
	}
	return w.String(), nil
}
