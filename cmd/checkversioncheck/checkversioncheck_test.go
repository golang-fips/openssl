package main

import (
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestOKVersion runs the analyzer against testdata/okversion and asserts
// no violations.
func TestOKVersion(t *testing.T) {
	got := analyze(t, "testdata/okversion")
	if len(got) != 0 {
		t.Fatalf("analyzer reported %d violation(s) on testdata/okversion, want 0:\n%s",
			len(got), strings.Join(got, "\n"))
	}
}

// TestBadVersion runs the analyzer against testdata/badversion and asserts
// that every `// want: <fn>` comment in the fixture corresponds to exactly
// one violation on the following line, and that the analyzer reports no
// violations on any other line.
func TestBadVersion(t *testing.T) {
	const dir = "testdata/badversion"

	want := wantedViolations(t, dir)
	got := analyze(t, dir)

	gotByLoc := make(map[string]string, len(got))
	gotLocRE := regexp.MustCompile(`^([^:]+):(\d+):\d+: unjustified version check (\w+)`)
	for _, line := range got {
		m := gotLocRE.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("could not parse analyzer output: %q", line)
		}
		key := m[1] + ":" + m[2]
		if prev, dup := gotByLoc[key]; dup {
			t.Fatalf("multiple violations reported at %s: %q and %q", key, prev, m[3])
		}
		gotByLoc[key] = m[3]
	}

	for loc, fn := range want {
		gotFn, ok := gotByLoc[loc]
		if !ok {
			t.Errorf("missing expected violation at %s (want %s)", loc, fn)
			continue
		}
		if gotFn != fn {
			t.Errorf("at %s: got %s, want %s", loc, gotFn, fn)
		}
		delete(gotByLoc, loc)
	}
	for loc, fn := range gotByLoc {
		t.Errorf("unexpected violation at %s: %s", loc, fn)
	}
}

// analyze runs checkFile on every .go file under dir and returns the
// captured analyzer output, one report per element. Output goes through
// the same code path the binary uses (fmt.Fprintf to os.Stderr) so any
// formatting bug shows up here too.
func analyze(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	sort.Strings(files)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = origStderr }()

	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		checkFile(fset, file)
	}
	w.Close()
	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	out := string(buf)
	if out == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(out, "\n"), "\n")
}

// wantedViolations parses `// want: <fn>` comments in dir's .go files and
// returns a map from "file:line" (where the violation is expected, i.e.
// the line *after* the marker) to the function name.
func wantedViolations(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	sort.Strings(files)
	out := make(map[string]string)

	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				const prefix = "// want:"
				if !strings.HasPrefix(c.Text, prefix) {
					continue
				}
				fn := strings.TrimSpace(strings.TrimPrefix(c.Text, prefix))
				line := fset.Position(c.Slash).Line + 1
				key := f + ":" + strconv.Itoa(line)
				if prev, dup := out[key]; dup {
					t.Fatalf("multiple `// want:` markers target %s: %q and %q", key, prev, fn)
				}
				out[key] = fn
			}
		}
	}
	return out
}
