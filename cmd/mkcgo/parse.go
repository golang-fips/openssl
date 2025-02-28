package main

import (
	"bufio"
	"cmp"
	"errors"
	"os"
	"slices"
	"strings"
)

type attribute struct {
	name         string
	description  string
	hasParameter bool
	handle       func(string, *fnAttributes)
}

var attributes = [...]attribute{
	{
		name:         "tag",
		description:  "the function will be loaded together with other functions with the same tag.",
		hasParameter: true,
		handle: func(s string, opts *fnAttributes) {
			opts.tag = s
		},
	},
	{
		name:         "variadic",
		description:  "the function has variadic arguments, and its name is a custom wrapper for the actual C name, defined in this attribute.",
		hasParameter: true,
		handle: func(s string, opts *fnAttributes) {
			opts.variadic = true
			opts.importName = s
		},
	},
}

// parseFiles parses files listed in fs and extracts all syscall
// functions listed in sys comments. It returns source files
// and functions collection *Source if successful.
func parseFiles(fs []string) (*source, error) {
	src := &source{
		funcs: make([]*fn, 0),
		stdLibImports: []string{
			"unsafe",
		},
		files:  fs,
		ctypes: make(map[string]struct{}),
	}
	for _, file := range fs {
		if err := src.parseFile(file); err != nil {
			return nil, err
		}
	}
	return src, nil
}

// parseFile parses file name and extracts all symbols.
func (src *source) parseFile(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	var inComment bool
	for s.Scan() {
		line := trim(s.Text())

		// Skip non-mkcgo comments.
		// If the line does not start with "/*[[mkcgo", check if it is a regular comment.
		if !strings.HasPrefix(line, "/*[[mkcgo") {
			if strings.HasPrefix(line, "/*") && !strings.HasSuffix(line, "*/") {
				inComment = true
			}
			if inComment && strings.HasSuffix(line, "*/") {
				inComment = false
			}
			continue
		}

		// Process mkcgo attribute lines.
		// Expect a closing "*/"; if not found, return an error.
		end := strings.LastIndex(line, "*/")
		if end == -1 {
			return errors.New("no closing attributes comment in line: " + line)
		}
		var fnOps fnAttributes
		// If the line starts with the attribute marker, extract attributes.
		if strings.HasPrefix(line, "/*[[mkcgo::") {
			if err = extractFunctionAttributes(line[2:end], &fnOps); err != nil {
				return err
			}
		}
		// Remove the comment block and continue processing.
		line = line[end+2:]
		if line == "" {
			continue
		}
		f, err := newFn(line, fnOps)
		if err != nil {
			return err
		}
		src.funcs = append(src.funcs, f)
	}
	if err := s.Err(); err != nil {
		return err
	}
	slices.SortFunc(src.funcs, func(fi, fj *fn) int {
		return cmp.Compare(fi.cName, fj.cName)
	})
	return nil
}

// newFn parses string s and return created function Fn.
func newFn(s string, opts fnAttributes) (*fn, error) {
	f := &fn{
		rets: &rets{},
		src:  s,
	}
	// function name and args
	prefix, body, _, found := extractSection(s, "(", ")")
	if !found || prefix == "" {
		return nil, errors.New("could not extract function name and parameters from \"" + f.src + "\"")
	}
	var err error
	f.params, err = extractParams(body)
	if err != nil {
		return nil, err
	}
	nameIdx := strings.LastIndexByte(prefix, ' ')
	if nameIdx < 0 || nameIdx+1 >= len(prefix) {
		return nil, errors.New("could not extract function name from \"" + f.src + "\"")
	}
	name, typ := trim(prefix[nameIdx+1:]), trim(prefix[:nameIdx])
	for strings.HasPrefix(name, "*") {
		name = name[1:]
		typ += "*"
	}
	f.cName = trim(name)
	if opts.importName != "" {
		f.importName = opts.importName
	} else {
		f.importName = f.cName
	}
	f.goName = "go_openssl_" + f.cName
	f.tag = opts.tag
	f.rets = &rets{
		typ:  trim(typ),
		name: "_r0",
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

// extractFunctionAttributes extracts mkcgo attributes from string s.
func extractFunctionAttributes(s string, attrs *fnAttributes) error {
	s = trim(s)
	if s == "" {
		return nil
	}
	for {
		var body string
		var ok bool
		_, body, s, ok = extractSection(s, "[[", "]]")
		if !ok {
			break
		}
		body, ok = strings.CutPrefix(body, "mkcgo::")
		if !ok {
			return errors.New("could not extract mkcgo attribute from \"" + body + "\"")
		}
		var handled bool
		for _, attr := range attributes {
			if (!attr.hasParameter && body != attr.name) ||
				(attr.hasParameter && !strings.HasPrefix(body, attr.name+"(")) {
				continue
			}
			var arg string
			if attr.hasParameter {
				if _, arg, _, ok = extractSection(body, "(", ")"); !ok {
					return errors.New("could not extract mkcgo attribute argument from \"" + body + "\"")
				}
				arg = strings.Trim(arg, `"`)
			}
			attr.handle(arg, attrs)
			handled = true
			break
		}
		if !handled {
			return errors.New("unknown mkcgo attribute: " + body)
		}
	}
	return nil
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
		ps = append(ps, &param{
			name:      sanitizeParamName(name),
			typ:       typ,
			tmpVarIdx: i,
		})
	}
	return ps, nil
}

// sanitizeParamName returns a sanitized version of the parameter name
// to avoid conflicts with Go keywords.
func sanitizeParamName(name string) string {
	name = trim(name)
	switch name {
	case "type", "func":
		name = "__" + name
	}
	return name
}
