package mkcgo

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

type FuncAttributes struct {
	Tags         []TagAttr
	VariadicInst bool
	ImportName   string
	Optional     bool
	NoError      bool
	ErrCond      string
	NoEscape     bool
	NoCallback   bool
}

type attribute struct {
	name        string
	description string
	handle      func(*FuncAttributes, ...string) error
}

var attributes = [...]attribute{
	{
		name:        "tag",
		description: "The function will be loaded together with other functions with the same tag. It can contain an optional name, which is the import name for the tag.",
		handle: func(opts *FuncAttributes, s ...string) error {
			var name string
			if len(s) > 1 {
				name = s[1]
			}
			opts.Tags = append(opts.Tags, TagAttr{Tag: s[0], Name: name})
			return nil
		},
	},
	{
		name:        "variadic",
		description: "The function has variadic arguments, and its name is a custom wrapper for the actual C name, defined in this attribute.",
		handle: func(opts *FuncAttributes, s ...string) error {
			opts.VariadicInst = true
			opts.ImportName = s[0]
			return nil
		},
	},
	{
		name:        "optional",
		description: "The function is optional",
		handle: func(opts *FuncAttributes, s ...string) error {
			opts.Optional = true
			return nil
		},
	},
	{
		name:        "noerror",
		description: "The function does not return an error, and the program will panic if the function returns an error.",
		handle: func(opts *FuncAttributes, s ...string) error {
			if opts.ErrCond != "" {
				return errors.New("noerror attribute is not allowed with errcond attribute")
			}
			opts.NoError = true
			return nil
		},
	},
	{
		name:        "errcond",
		description: "The function returns an error if the C function returns a value that matches the condition in this attribute.",
		handle: func(opts *FuncAttributes, s ...string) error {
			if opts.NoError {
				return errors.New("errcond attribute is not allowed with noerror attribute")
			}
			opts.ErrCond = s[0]
			return nil
		},
	},
	{
		name:        "noescape",
		description: "The C function does not keep a copy of the Go pointer.",
		handle: func(opts *FuncAttributes, s ...string) error {
			opts.NoEscape = true
			return nil
		},
	},
	{
		name:        "nocallback",
		description: "The C function does not call back into Go.",
		handle: func(opts *FuncAttributes, s ...string) error {
			opts.NoCallback = true
			return nil
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
		return cmp.Compare(fi.Name, fj.Name)
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
		if line == "" {
			// Skip empty lines.
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

		// Process preprocessor directives.
		if strings.HasPrefix(line, "#") {
			if v, ok := strings.CutPrefix(line, "#include "); ok {
				src.Includes = append(src.Includes, v)
			}
			// Skip all other preprocessor directives.
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
		var fnOps FuncAttributes
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
func newFn(s string, attrs FuncAttributes) (*Func, error) {
	// function name and args
	prefix, body, _, found := extractSection(s, "(", ")")
	if !found || prefix == "" {
		return nil, errors.New("could not extract function name and parameters from \"" + s + "\"")
	}
	fn := &Func{
		FuncAttributes: attrs,
		Ret:            &Return{},
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
	name, typ := normalizeParam(prefix[nameIdx+1:], prefix[:nameIdx])
	fn.Name = name
	if attrs.ImportName != "" {
		fn.ImportName = attrs.ImportName
	} else {
		fn.ImportName = name
	}
	fn.Ret = &Return{
		Type: trim(typ),
		Name: "_r0",
	}
	return fn, nil
}

// normalizeParam normalizes parameter name and type.
func normalizeParam(name, typ string) (string, string) {
	name, typ = trim(name), trim(typ)
	// Remove leading asterisks from the name and add them to the type.
	for strings.HasPrefix(name, "*") {
		name = name[1:]
		typ += "*"
	}
	switch name {
	case "type", "func":
		name = "__" + name
	}
	// Remove all spaces between the asterisks and the type.
	typ = strings.ReplaceAll(typ, " *", "*")
	return trim(name), trim(typ)
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
	idxStart := strings.Index(body, start)
	idxEnd := strings.Index(body, end)
	needBalancing := idxStart != -1 && idxEnd != -1 && idxStart < idxEnd
	if !needBalancing {
		a := strings.SplitN(body, end, 2)
		if len(a) != 2 {
			return "", "", "", false
		}
		return prefix, a[0], a[1], true
	}
	depth := 1
	for i := range len(body) {
		if strings.HasPrefix(body[i:], start) {
			depth++
		} else if strings.HasPrefix(body[i:], end) {
			depth--
			if depth == 0 {
				return prefix, body[:i], body[i+len(end):], true
			}
		}
	}
	return "", "", s, false
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
// described in https://gcc.gnu.org/onlinedocs/gcc/Attribute-Syntax.html.
func extractFunctionAttributes(s string, fnAttrs *FuncAttributes) (string, error) {
	// There can be spaces between __attribute__ and the opening parenthesis.
	prefix, body, found := strings.Cut(s, "__attribute__")
	if !found {
		return s, nil
	}
	_, body, suffix, found := extractSection(body, "(", ")")
	if !found {
		return s, nil
	}
	if !strings.HasPrefix(body, "(") || !strings.HasSuffix(body, ")") {
		// Attributes are enclosed in double parentheses.
		return s, nil
	}
	body = trim(body[1 : len(body)-1])
	for {
		if body == "" {
			break
		}
		// Attributes are separated by commas. Get the next attribute.
		// We can't just use strings.Split because the attribute argument
		// can contain commas.
		var name, args string
		idxComma := strings.IndexByte(body, ',')
		idxParen := strings.IndexByte(body, '(')
		if idxComma != -1 && (idxParen == -1 || idxComma < idxParen) {
			// The attribute has no arguments.
			name = body[:idxComma]
			body = body[idxComma+1:]
		} else if idxParen != -1 && (idxComma == -1 || idxComma > idxParen) {
			// The attribute has arguments, possibly with commas.
			name = body[:idxParen]
			_, args, body, found = extractSection(body[idxParen:], "(", ")")
			if !found {
				return "", errors.New("unbalanced parentheses in line: " + s)
			}
			body = trim(body)
			if len(body) > 0 && body[0] != ',' {
				return "", errors.New("parameters must be separated by commas in line: " + s)
			}
			body = strings.TrimPrefix(body, ",")
		} else if idxComma == -1 && idxParen == -1 {
			// The attribute has no arguments and is the last one.
			name = body
			body = ""
		}
		name, args = trim(name), trim(args)
		var handled bool
		for _, attr := range attributes {
			if name != attr.name {
				continue
			}
			vargs := strings.Split(args, ",")
			for i := range vargs {
				vargs[i] = trim(strings.Trim(vargs[i], `"`))
			}
			if err := attr.handle(fnAttrs, vargs...); err != nil {
				return "", fmt.Errorf("error parsing attribute in line: %v: %w", s, err)
			}
			handled = true
			break
		}
		if !handled {
			return "", errors.New("unknown mkcgo attribute: " + name)
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
			name, typ = s2[b+1:], s2[:b]
		} else {
			typ = s2
		}
		name, typ = normalizeParam(name, typ)
		ps = append(ps, &Param{
			Name: name,
			Type: typ,
		})
	}
	return ps, nil
}
