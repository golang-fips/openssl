// versionguardcheck is a small static analyzer that enforces the
// "version checks must be justified" rule.
//
// It walks the OpenSSL backend's package ASTs and flags any call to
// minor(), patch(), versionAtOrAbove(), or checkMajorVersion() that appears
// inside the OpenSSL 3+ branch of a `switch major()` statement, unless the
// call is annotated with a marker comment of the form:
//
//	//versionguardcheck:ignore <reason>
//
// placed on the line immediately above the call. The marker comment is the
// source of truth for *why* the check exists and *what versions it covers*;
// any link in the comment is supporting context. Calls to major() are
// exempt because the outer `switch major()` between the 1.x and 3+ branches
// is the deliberate top-level dispatch.
//
// Usage:
//
//	go run ./cmd/versionguardcheck [packages...]
//
// With no arguments, the current directory is analyzed. Package arguments
// are interpreted as filesystem paths (one per Go package directory).
//
// Exits non-zero if any unjustified version check is found, or if any input
// file fails to parse.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const markerPrefix = "//versionguardcheck:ignore"

// gatedFns are the unqualified function names whose calls inside the
// OpenSSL 3+ branch must be justified by a //versionguardcheck:ignore marker.
//
// major() is intentionally excluded: the outer `switch major()` between
// the 1.x and 3+ branches is the top-level dispatch and is exempt.
var gatedFns = map[string]bool{
	"minor":             true,
	"patch":             true,
	"versionAtOrAbove":  true,
	"checkMajorVersion": true,
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: versionguardcheck [packages...]")
		flag.PrintDefaults()
	}
	flag.Parse()
	dirs := flag.Args()
	if len(dirs) == 0 {
		dirs = []string{"."}
	}

	var bad int
	for _, dir := range dirs {
		n, err := checkDir(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "versionguardcheck:", err)
			os.Exit(2)
		}
		bad += n
	}
	if bad > 0 {
		fmt.Fprintf(os.Stderr, "versionguardcheck: %d unjustified version check(s)\n", bad)
		os.Exit(1)
	}
}

// checkDir analyzes every Go package directory rooted at dir (recursively).
// Test files are skipped: the //versionguardcheck:ignore convention applies to
// production code only.
func checkDir(dir string) (int, error) {
	var bad int
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		if base != "." && (base == "testdata" || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_")) {
			return filepath.SkipDir
		}
		n, err := checkPkg(path)
		if err != nil {
			return err
		}
		bad += n
		return nil
	})
	return bad, err
}

// checkPkg parses every non-test .go file directly under dir (non-recursive)
// and runs the analyzer on each one.
func checkPkg(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	sort.Strings(files)

	fset := token.NewFileSet()
	var bad int
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			return 0, err
		}
		bad += checkFile(fset, file)
	}
	return bad, nil
}

// checkFile reports unjustified gated calls inside any 3+ branch of a
// `switch major()` in file.
func checkFile(fset *token.FileSet, file *ast.File) int {
	marked := markedLines(fset, file)
	var bad int
	var visit func(n ast.Node, in3Plus bool)
	visit = func(n ast.Node, in3Plus bool) {
		if n == nil {
			return
		}
		// When we hit `switch major() { ... }`, recurse into each case
		// clause with in3Plus set according to the case's value list.
		if sw, ok := n.(*ast.SwitchStmt); ok && isMajorSwitch(sw.Tag) {
			if sw.Init != nil {
				visit(sw.Init, in3Plus)
			}
			for _, stmt := range sw.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				childIn3Plus := isThreePlusClause(cc)
				for _, s := range cc.Body {
					visit(s, childIn3Plus)
				}
			}
			return
		}
		if in3Plus {
			if call, ok := n.(*ast.CallExpr); ok {
				if id := gatedCallee(call); id != nil {
					pos := fset.Position(call.Pos())
					if !marked[pos.Line-1] {
						bad++
						fmt.Fprintf(os.Stderr,
							"%s:%d:%d: unjustified version check %s(...): add a //versionguardcheck:ignore <reason> comment on the line above\n",
							pos.Filename, pos.Line, pos.Column, id.Name)
					}
				}
			}
		}
		// Recurse into immediate children.
		for _, c := range childNodes(n) {
			visit(c, in3Plus)
		}
	}
	for _, decl := range file.Decls {
		visit(decl, false)
	}
	return bad
}

// markedLines returns the set of source-line numbers that bear a
// well-formed //versionguardcheck:ignore comment.
func markedLines(fset *token.FileSet, file *ast.File) map[int]bool {
	out := make(map[int]bool)
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if !isMarker(c.Text) {
				continue
			}
			out[fset.Position(c.Slash).Line] = true
		}
	}
	return out
}

// isMarker reports whether text is //versionguardcheck:ignore followed by
// whitespace and a non-empty reason.
func isMarker(text string) bool {
	rest, ok := strings.CutPrefix(text, markerPrefix)
	if !ok {
		return false
	}
	if rest == "" {
		return false
	}
	if rest[0] != ' ' && rest[0] != '\t' {
		return false
	}
	return strings.TrimSpace(rest) != ""
}

// gatedCallee returns the identifier of call's callee if call is an
// unqualified call to one of [gatedFns], otherwise nil. Method calls
// (x.minor()) and qualified calls (pkg.minor()) are not flagged: the
// helpers we care about are package-level functions in the openssl
// package and are always called unqualified.
func gatedCallee(call *ast.CallExpr) *ast.Ident {
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return nil
	}
	if !gatedFns[id.Name] {
		return nil
	}
	return id
}

// isMajorSwitch reports whether tag is a call to the local major() helper.
func isMajorSwitch(tag ast.Expr) bool {
	call, ok := tag.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	return id.Name == "major"
}

// isThreePlusClause reports whether cc is a case clause whose value list
// matches an OpenSSL 3+ major version. The default clause and any clause
// whose values do not include 1 are treated as 3+; a clause that lists 1
// is treated as 1.x and is not flagged.
func isThreePlusClause(cc *ast.CaseClause) bool {
	if len(cc.List) == 0 {
		return true
	}
	hasOne := false
	hasOther := false
	for _, e := range cc.List {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.INT {
			continue
		}
		if bl.Value == "1" {
			hasOne = true
		} else {
			hasOther = true
		}
	}
	return hasOther && !hasOne
}

// childNodes returns the immediate AST children of n in source order.
func childNodes(n ast.Node) []ast.Node {
	var out []ast.Node
	ast.Inspect(n, func(c ast.Node) bool {
		if c == n || c == nil {
			return true
		}
		out = append(out, c)
		return false
	})
	return out
}
