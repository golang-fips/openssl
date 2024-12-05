package main

import (
	"bufio"
	"cmp"
	"errors"
	"os"
	"slices"
	"strings"
)

// parseFiles parses files listed in fs and extracts all syscall
// functions listed in sys comments. It returns source files
// and functions collection *Source if successful.
func parseFiles(fs []string) (*source, error) {
	src := &source{
		funcs: make([]*fn, 0),
		stdLibImports: []string{
			"unsafe",
		},
		files: fs,
	}
	for _, file := range fs {
		if err := src.parseFile(file); err != nil {
			return nil, err
		}
	}
	return src, nil
}

func (src *source) parseFile(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	var inComment bool
	var srcOps, fnOps fnOptions
	var t string
	for s.Scan() {
		line := trim(s.Text())
		if strings.HasPrefix(line, "/*") {
			if !strings.HasSuffix(line, "*/") {
				inComment = true
			}
			continue
		}
		if inComment && strings.HasSuffix(line, "*/") {
			inComment = false
			continue
		}
		if inComment {
			continue
		}
		if t, ok := strings.CutPrefix(line, "//mkcgo:"); ok {
			if v, ok := strings.CutPrefix(t, "failCondition "); ok {
				srcOps.failCondition = v
				fnOps.failCondition = v
				continue
			}
			return errors.New("Unknown mkcgo directive: " + t)
		}

		if strings.HasPrefix(line, "[[") {
			for {
				var body string
				var ok bool
				_, body, line, ok = extractSection(line, "[[", "]]")
				if !ok {
					break
				}
				body, ok = strings.CutPrefix(body, "mkcgo::")
				if !ok {
					continue
				}
				if body == "error" {
					fnOps.returnsError = true
				} else if body == "error_only" {
					fnOps.returnsError = true
					fnOps.errorOnly = true
				} else if body == "c_only" {
					fnOps.cOnly = true
				} else if strings.HasPrefix(body, "error(") || strings.HasPrefix(body, "error_only(") {
					fnOps.returnsError = true
					fnOps.errorOnly = strings.HasPrefix(body, "error_only(")
					if _, body, _, ok = extractSection(body, "(", ")"); ok {
						fnOps.failCondition = strings.Trim(body, `"`)
					}
				} else if strings.HasPrefix(body, "name(") {
					if _, body, _, ok = extractSection(body, "(", ")"); ok {
						fnOps.name = strings.Trim(body, `"`)
					}
				} else if strings.HasPrefix(body, "variadic(") {
					if _, body, _, ok = extractSection(body, "(", ")"); ok {
						fnOps.importName = strings.Trim(body, `"`)
					}
				}
			}
		}

		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "" {
			continue
		}
		if t != "" {
			t += " "
		}
		t += line
		if !strings.HasSuffix(line, ";") {
			// Accept multiline lines
			continue
		}
		f, err := newFn(t, fnOps)
		if err != nil {
			return err
		}
		src.funcs = append(src.funcs, f)
		fnOps = fnOptions{
			errorType:     srcOps.errorType,
			failCondition: srcOps.failCondition,
		}
		t = ""
	}
	if err := s.Err(); err != nil {
		return err
	}
	slices.SortFunc(src.funcs, func(fi, fj *fn) int {
		return cmp.Compare(fi.libName, fj.libName)
	})
	return nil
}

// newFn parses string s and return created function Fn.
func newFn(s string, opts fnOptions) (*fn, error) {
	f := &fn{
		rets: &rets{},
		src:  s,
	}
	// function name and args
	prefix, body, s, found := extractSection(s, "(", ")")
	if !found || prefix == "" {
		return nil, errors.New("Could not extract function name and parameters from \"" + f.src + "\"")
	}
	var err error
	f.params, err = extractParams(body)
	if err != nil {
		return nil, err
	}
	nameIdx := strings.LastIndexByte(prefix, ' ')
	if nameIdx < 0 || nameIdx+1 >= len(prefix) {
		return nil, errors.New("Could not extract function name from \"" + f.src + "\"")
	}
	name, typ := trim(prefix[nameIdx+1:]), trim(prefix[:nameIdx])
	for strings.HasPrefix(name, "*") {
		name = name[1:]
		typ += "*"
	}
	f.libName = trim(name)
	if opts.importName != "" {
		f.importName = opts.importName
	} else {
		f.importName = f.libName
	}
	if opts.name != "" {
		f.name = opts.name
	} else {
		f.name = f.libName
	}
	f.cOnly = opts.cOnly
	f.rets = &rets{
		typ:          trim(typ),
		name:         "_r0",
		returnsError: opts.returnsError,
		errorOnly:    opts.errorOnly,
		failCond:     opts.failCondition,
	}
	return f, nil
}

// trim returns s with leading and trailing spaces and tabs removed.
func trim(s string) string {
	return strings.Trim(s, " \t")
}

// extractSection extracts text out of string s starting after start
// and ending just before end. found return value will indicate success,
// and prefix, body and suffix will contain correspondent parts of string s.
func extractSection(s string, start, end string) (prefix, body, suffix string, found bool) {
	s = trim(s)
	if v, ok := strings.CutPrefix(s, start); ok {
		// no prefix
		body = v
	} else {
		a := strings.SplitN(s, start, 2)
		if len(a) != 2 {
			return "", "", s, false
		}
		prefix = a[0]
		body = a[1][len(start)-1:]
	}
	a := strings.SplitN(body, end, 2)
	if len(a) != 2 {
		return "", "", "", false
	}
	return prefix, a[0], a[1], true
}

// extractParams parses s to extract function parameters.
func extractParams(s string) ([]*param, error) {
	s = trim(s)
	if s == "" {
		return nil, nil
	}
	a := strings.Split(s, ",")
	ps := make([]*param, 0, len(a))
	for i := range a {
		s2 := trim(a[i])
		if i == len(a)-1 && s2 == "..." {
			break // omit variadic argument
		}
		b := strings.LastIndexByte(s2, ' ')
		var name, typ string
		if b != -1 {
			name, typ = trim(s2[b+1:]), trim(s2[:b])
		} else {
			typ = trim(s2)
		}
		for strings.HasPrefix(name, "*") {
			name = name[1:]
			typ += "*"
		}
		name = trim(name)
		ps = append(ps, &param{
			name:      name,
			typ:       typ,
			tmpVarIdx: i,
		})
	}
	return ps, nil
}
