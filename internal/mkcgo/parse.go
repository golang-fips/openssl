package mkcgo

import (
	"bufio"
	"cmp"
	"errors"
	"os"
	"slices"
	"strings"
)

type fnAttributes struct {
	tag        string
	variadic   bool
	importName string
}

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

// Parse parses files listed in fs and extracts all syscall
// functions listed in sys comments. It returns source files
// and functions collection *Source if successful.
func Parse(fs ...string) (*Source, error) {
	src := &Source{
		Files: fs,
	}
	for _, file := range fs {
		if err := src.parseFile(file); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(src.Funcs, func(fi, fj *Func) int {
		return cmp.Compare(fi.CName, fj.CName)
	})
	return src, nil
}

// parseFile parses file name and extracts all symbols.
func (src *Source) parseFile(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	var inBlockComment, inEnum bool
	for s.Scan() {
		line := trim(s.Text())
		// Process comments.
		comment, line := processComments(line, &inBlockComment)
		comment = trim(comment)
		if comment != "" {
			if inBlockComment {
				// The comment is inside a block comment.
				// Append it to the previous comment.
				src.Comments[len(src.Comments)-1] += "\n" + comment
			} else {
				src.Comments = append(src.Comments, comment)
			}
		}
		line = trim(line)
		if line == "" || line[0] == '#' {
			// Skip empty lines and preprocessor directives.
			continue
		}

		if inEnum {
			if strings.HasPrefix(line, "};") {
				inEnum = false
				continue
			}
			enum, err := newEnum(line)
			if err != nil {
				return err
			}
			src.Enums = append(src.Enums, enum)
			continue
		}
		if strings.HasPrefix(line, "enum {") {
			inEnum = true
			continue
		}

		// Process typedefs.
		if strings.Contains(line, "typedef ") {
			td, err := newTypeDef(line)
			if err != nil {
				return err
			}
			src.TypeDefs = append(src.TypeDefs, td)
			continue
		}

		// Process attributes.
		var fnOps fnAttributes
		line, err = extractFunctionAttributes(line, &fnOps)
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}

		// Process function.
		f, err := newFn(line, fnOps)
		if err != nil {
			return err
		}
		src.Funcs = append(src.Funcs, f)
	}
	if err := s.Err(); err != nil {
		return err
	}
	return nil
}

// newEnum parses string s and returns created enum definition Enum.
func newEnum(line string) (*Enum, error) {
	line = strings.TrimSuffix(line, ",")
	split := strings.SplitN(line, "=", 2)
	if len(split) != 2 {
		return nil, errors.New("could not extract enum value from \"" + line + "\"")
	}
	return &Enum{
		Name:  trim(split[0]),
		Value: trim(split[1]),
	}, nil
}

// newTypeDef parses string s and returns created type definition TypeDef.
func newTypeDef(line string) (*TypeDef, error) {
	after, found := strings.CutPrefix(line, "typedef ")
	if !found {
		return nil, errors.New("could not extract typedef from \"" + line + "\"")
	}
	after = strings.TrimSuffix(after, ";")
	idx := strings.LastIndex(after, " ")
	if idx < 0 {
		return nil, errors.New("could not extract type name from \"" + after + "\"")
	}
	return &TypeDef{
		Name: trim(after[idx+1:]),
		Type: trim(after[:idx]),
	}, nil
}

// newFn parses string s and return created function Fn.
func newFn(s string, opts fnAttributes) (*Func, error) {
	// function name and args
	prefix, body, _, found := extractSection(s, "(", ")")
	if !found || prefix == "" {
		return nil, errors.New("could not extract function name and parameters from \"" + s + "\"")
	}
	fn := &Func{
		Ret:      &Return{},
		Variadic: opts.variadic,
		Tag:      opts.tag,
	}
	var err error
	fn.Params, err = extractParams(body)
	if err != nil {
		return nil, err
	}
	nameIdx := strings.LastIndexByte(prefix, ' ')
	if nameIdx < 0 || nameIdx+1 >= len(prefix) {
		return nil, errors.New("could not extract function name from \"" + s + "\"")
	}
	name, typ := trim(prefix[nameIdx+1:]), trim(prefix[:nameIdx])
	for strings.HasPrefix(name, "*") {
		name = name[1:]
		typ += "*"
	}
	fn.CName = trim(name)
	if opts.importName != "" {
		fn.ImportName = opts.importName
	} else {
		fn.ImportName = fn.CName
	}
	fn.GoName = "go_openssl_" + fn.CName
	fn.Ret = &Return{
		Type: trim(typ),
		Name: "_r0",
	}
	return fn, nil
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
		body = a[1]
	}
	a := strings.SplitN(body, end, 2)
	if len(a) != 2 {
		return "", "", "", false
	}
	return prefix, a[0], a[1], true
}

// processComments removes comments from line and returns the result.
// inBlockComment is true if the line is inside a block comment.
func processComments(line string, inBlockComment *bool) (comment, remmaining string) {
	if *inBlockComment {
		// Remove the rest of the block comment.
		var found bool
		comment, line, found = strings.Cut(line, "*/")
		if !found {
			return comment, ""
		}
		*inBlockComment = false
	}
	// Remove line comments.
	if before, comment, found := strings.Cut(line, "//"); found {
		return comment, before
	}
	// Remove block comments.
	if prefix, _, suffix, found := extractSection(line, "/*", "*/"); found {
		line = prefix + suffix
	}
	// Remove block comments that span multiple lines.
	if line, comment, *inBlockComment = strings.Cut(line, "/*"); *inBlockComment {
		return comment, line
	}
	return "", line
}

// extractFunctionAttributes extracts mkcgo attributes from string s.
// The attributes format follows the GCC __attribute__ syntax as
// described in https://gcc.gnu.org/onlinedocs/gcc/Function-Attributes.html.
func extractFunctionAttributes(s string, fnAttrs *fnAttributes) (string, error) {
	prefix, body, suffix, found := extractSection(s, "__attribute__((", "));")
	if !found {
		return s, nil
	}
	for _, v := range strings.Split(body, ",") {
		v = trim(v)
		var handled bool
		for _, attr := range attributes {
			if (!attr.hasParameter && v != attr.name) ||
				(attr.hasParameter && !strings.HasPrefix(v, attr.name+"(")) {
				continue
			}
			var arg string
			if attr.hasParameter {
				var ok bool
				if _, arg, _, ok = extractSection(v, "(", ")"); !ok {
					return "", errors.New("could not extract mkcgo attribute argument from \"" + v + "\"")
				}
				arg = strings.Trim(arg, `"`)
			}
			attr.handle(arg, fnAttrs)
			handled = true
			break
		}
		if !handled {
			return "", errors.New("unknown mkcgo attribute: " + v)
		}
	}
	return trim(prefix + suffix), nil
}

// extractParams parses s to extract function parameters.
func extractParams(s string) ([]*Param, error) {
	s = trim(s)
	if s == "" {
		return nil, nil
	}
	a := strings.Split(s, ",")
	ps := make([]*Param, 0, len(a))
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
		ps = append(ps, &Param{
			Name: sanitizeParamName(name),
			Type: typ,
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
