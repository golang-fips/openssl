package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
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
// - Typedefs following the pattern "typedef void* GO_%name%_PTR" are translated into "#define %name% GO_%name%_PTR".
// - Enums are validated against their definition in the OpenSSL headers. Example:
//   "enum { GO_EVP_CTRL_GCM_SET_TAG = 0x11 }" => "_Static_assert(EVP_CTRL_GCM_SET_TAG == 0x11);"
// - Function macros are validated against their definition in the OpenSSL headers. Example:
//   "DEFINEFUNC(int, RAND_bytes, (unsigned char *a0, int a1), (a0, a1))" => "int(*__check_0)(unsigned char *, int) = RAND_bytes;"
// - Function macros are excluded when checking old OpenSSL versions if they are prepended with '/*check:from=%version%*/', %version% being a version string such as '1.1.1' or '3.0.0'.

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
		"-c",                           // skip linking
		"-Werror",                      // promote all warnings to errors
		"-Wno-deprecated-declarations", // deprecation warnings are expected
		"-isystem", *osslInclude,       // OpenSSL include from --ossl-include must be preferred over system includes
		"-o", "/dev/null", // discard output
		name)
	p.Stdout = os.Stdout
	p.Stderr = os.Stderr
	return p.Run()
}

func generate(header string) (string, error) {
	f, err := os.Open(header)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var b strings.Builder
	sc := bufio.NewScanner(f)
	var i int
	var enum bool
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if enum {
			if !strings.HasPrefix(l, "}") {
				tryConvertEnum(&b, l)
			} else {
				enum = false
			}
			continue
		}
		if strings.HasPrefix(l, "enum {") || strings.HasPrefix(l, "typedef enum {") {
			enum = true
			continue
		}
		if tryConvertDirective(&b, l) {
			continue
		}
		if tryConvertTypedef(&b, l) {
			continue
		}
		if tryConvertDefineFunc(&b, l, i) {
			i++
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func tryConvertDirective(w io.Writer, l string) bool {
	if strings.HasPrefix(l, "// #") {
		fmt.Fprintln(w, l[len("// "):])
		return true
	}
	return false
}

// tryConvertTypedef converts a typedef contained in the line l
// into a #define pointing to the corresponding OpenSSL type.
// Only void* typedefs starting with GO_ are converted.
// If l does not contain a typedef it does nothing and returns false.
func tryConvertTypedef(w io.Writer, l string) bool {
	if !strings.HasPrefix(l, "typedef void* GO_") {
		return false
	}
	// Replace custom opaque pointer typedef with the proper OpenSSL type
	// so gcc does not complain about pointer mismatch.
	i1 := strings.Index(l, "GO_")
	i2 := strings.Index(l, "_PTR")
	if i2 < 0 {
		log.Println("unexpected line in typedef: " + l)
		return false
	}
	name := l[i1+len("GO_") : i2]
	fmt.Fprintf(w, "#define GO_%s_PTR %s*\n", name, name)
	return true
}

// tryConvertEnum adds a static check which verifies that
// the enum contained in the line l
// matches the corresponding OpenSSL value.
// Only enum names starting with GO_ are converted.
func tryConvertEnum(w io.Writer, l string) {
	if !strings.HasPrefix(l, "GO_") {
		return
	}
	if l[len(l)-1] == ',' {
		l = l[:len(l)-1]
	}
	split := strings.SplitN(l, " = ", 2)
	if len(split) < 2 {
		log.Printf("unexpected enum definition in function line: %s\n", l)
		return
	}
	name := split[0][len("GO_"):]
	fmt.Fprintf(w, "#ifdef %s\n", name)
	fmt.Fprintf(w, "_Static_assert(%s == %s, \"%s\");\n", name, split[1], name)
	fmt.Fprintln(w, "#endif")
}

// tryConvertDefineFunc adds a static check which verifies that
// the function definition macro contained in the line l
// matches the corresponding OpenSSL function signature.
// If l does not contain a function definition macro
// it does nothing and returns false.
// i is used to create a unique name: if tryConvertDefineFunc returns true,
// the same value of i must not be passed again in a future call.
// The value of i should be generated by a counter.
func tryConvertDefineFunc(w io.Writer, l string, i int) bool {
	var versionCond string
	if strings.HasPrefix(l, "/*check:from=") {
		i1 := strings.Index(l, "=")
		i2 := strings.Index(l, "*/")
		if i1 < 0 || i2 < 0 {
			log.Fatalln("unexpected 'check:from' condition: " + l)
		}
		from := l[i1+1 : i2]
		switch from {
		case "1.1.0":
			versionCond = "OPENSSL_VERSION_NUMBER >= 0x10100000L"
		case "1.1.1":
			versionCond = "OPENSSL_VERSION_NUMBER >= 0x10101000L"
		case "3.0.0":
			versionCond = "OPENSSL_VERSION_NUMBER >= 0x30000000L"
		default:
			log.Println("unexpected 'check:from' version" + l)
			return false
		}
		if l[i2+2] != ' ' {
			log.Fatalln("missing space between 'check:from' condition and function macro: " + l)
		}
		l = l[i2+3:]
	}
	if !strings.HasPrefix(l, "DEFINEFUNC") {
		return false
	}
	i1 := strings.IndexByte(l, '(')
	// The first ")," match is always the end of the argument list parameter.
	// We are not interested in the last parameter and parsing them would complicate the algorithm.
	// Matching against ')' is not enough as it also appears when the argument list parameter contains function pointers.
	i2 := strings.Index(l, "),")
	if i1 < 0 || i2 < 0 {
		log.Println("unexpected argument list in function line: " + l)
		return false
	}
	subs := l[i1+1 : i2+1]
	writeCheck := func(ret, name, args string) {
		fmt.Fprintf(w, "%s(*__check_%d)%s = %s;\n", ret, i, args, name)
	}
	writeDefineFunc := func(cond string) {
		args := strings.SplitN(subs, ",", 3)
		if len(args) < 3 {
			log.Printf("wrong number of function macro arguments in line: %s\n", l)
			return
		}
		fnret, fnname, fnargs := args[0], args[1], args[2]
		if cond != "" {
			fmt.Fprintf(w, "#if %s\n", cond)
		}
		if fnret == "" || fnname == "" || fnargs == "" {
			log.Printf("empty function macro arguments in line: %s\n", l)
			return
		}
		writeCheck(fnret, fnname, fnargs)
		if cond != "" {
			fmt.Fprintln(w, "#endif")
		}
	}
	writeDefineFuncRename := func(cond string) {
		args := strings.SplitN(subs, ",", 4)
		if len(args) < 4 {
			log.Printf("wrong number of function macro arguments in line: %s\n", l)
			return
		}
		fnret, fnname, fnoldname, fnargs := args[0], args[1], args[2], args[3]
		if fnret == "" || fnname == "" || fnoldname == "" || fnargs == "" {
			log.Printf("empty function macro arguments in line: %s\n", l)
			return
		}
		fmt.Fprintf(w, "#if %s\n", cond)
		writeCheck(fnret, fnoldname, fnargs)
		fmt.Fprintln(w, "#else")
		writeCheck(fnret, fnname, fnargs)
		fmt.Fprintln(w, "#endif")
	}
	if versionCond != "" {
		fmt.Fprintf(w, "#if %s\n", versionCond)
	}
	switch l[:i1] {
	case "DEFINEFUNC":
		writeDefineFunc("")
	case "DEFINEFUNC_LEGACY_1_0":
		writeDefineFunc("OPENSSL_VERSION_NUMBER < 0x10100000L")
	case "DEFINEFUNC_LEGACY_1":
		writeDefineFunc("OPENSSL_VERSION_NUMBER < 0x30000000L")
	case "DEFINEFUNC_1_1":
		writeDefineFunc("OPENSSL_VERSION_NUMBER >= 0x10100000L")
	case "DEFINEFUNC_1_1_1":
		writeDefineFunc("OPENSSL_VERSION_NUMBER >= 0x10101000L")
	case "DEFINEFUNC_3_0":
		writeDefineFunc("OPENSSL_VERSION_NUMBER >= 0x30000000L")
	case "DEFINEFUNC_RENAMED_1_1":
		writeDefineFuncRename("OPENSSL_VERSION_NUMBER < 0x10100000L")
	case "DEFINEFUNC_RENAMED_3_0":
		writeDefineFuncRename("OPENSSL_VERSION_NUMBER < 0x30000000L")
	default:
		log.Printf("unexpected function macro in line: %s\n", l)
	}
	if versionCond != "" {
		fmt.Fprintln(w, "#endif")
	}
	return true
}
