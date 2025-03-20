package mkcgo

import (
	"slices"
)

// Source is a collection of type definitions and functions.
type Source struct {
	TypeDefs []*TypeDef
	Enums    []*Enum
	Funcs    []*Func
	Files    []string
	Comments []string // All line comments. Directives in this slice start with "#"
	Includes []string // All #include directives, without the #include prefix.
}

// TypeDef describes a type definition.
type TypeDef struct {
	Name string
	Type string
}

// Enum describes an enum definition.
type Enum struct {
	Name  string
	Value string
}

// Func describes a function.
type Func struct {
	FuncAttributes
	Name   string
	Params []*Param
	Ret    *Return
}

func (f *Func) Variadic() bool {
	return len(f.Params) > 0 && f.Params[len(f.Params)-1].Variadic()
}

// TagAttr is an attribute of a tag with an optional name.
type TagAttr struct {
	Tag  string
	Name string
}

// Param is a function parameter.
type Param struct {
	Name string
	Type string
}

func (p *Param) Variadic() bool {
	return p.Type == "..."
}

// Return is a function return value.
type Return struct {
	Name string
	Type string
}

func (src *Source) Tags() []string {
	tags := make([]string, 0, len(src.Funcs)+1)
	tags = append(tags, "") // default tag
	for _, fn := range src.Funcs {
		for _, tag := range fn.Tags {
			if !slices.Contains(tags, tag.Tag) {
				tags = append(tags, tag.Tag)
			}
		}
	}
	slices.Sort(tags)
	return tags
}
