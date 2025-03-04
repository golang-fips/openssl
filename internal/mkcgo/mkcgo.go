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
	Comments []string // Directives starting with "// #"
}

// TypeDef describes a type definition.
type TypeDef struct {
	Name string
	Type string
}

type Enum struct {
	Name  string
	Value string
}

// Func describes a function.
type Func struct {
	GoName     string
	CName      string
	ImportName string
	Tag        string
	Params     []*Param
	Ret        *Return
	Variadic   bool
}

// Param is a function parameter.
type Param struct {
	Name string
	Type string
}

func (p *Param) IsVariadic() bool {
	return p.Type == "..."
}

// Return is a function return value.
type Return struct {
	Name string
	Type string
}

func (src *Source) Tags() []string {
	var tags []string
	for _, fn := range src.Funcs {
		if !slices.Contains(tags, fn.Tag) {
			tags = append(tags, fn.Tag)
		}
	}
	slices.Sort(tags)
	return tags
}
