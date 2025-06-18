// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/mitchellh/go-wordwrap"

	"github.com/cilium/cilium/pkg/datapath/config"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Common acronyms to transform into stylized form for Go field names.
var stylized = map[string]string{
	"bpf":     "BPF",
	"lxc":     "LXC",
	"xdp":     "XDP",
	"ipv4":    "IPv4",
	"ipv6":    "IPv6",
	"nat":     "NAT",
	"mac":     "MAC",
	"mtu":     "MTU",
	"id":      "ID",
	"ip":      "IP",
	"netns":   "NetNS",
	"ipcache": "IPCache",
}

// varsToStruct generates a Go struct from the configuration variables in the
// CollectionSpec.
func varsToStruct(spec *ebpf.CollectionSpec, name, kind, comment string, embeds []string) (string, error) {
	type field struct {
		comment  string
		goName   string
		cName    string
		typ      string
		defValue string
	}

	kind = "kind:" + kind

	fields := make([]field, 0, len(spec.Variables))

	for n, v := range spec.Variables {
		// Only consider variables in a specific config section to avoid interfering
		// with unrelated objects.
		if v.MapName() != config.Section {
			continue
		}

		// DECLARE_CONFIG prefixes the variable name with a well-known prefix to
		// avoid collisions with other variables with common names.
		n = strings.TrimPrefix(n, config.ConstantPrefix)

		if v.Type() == nil {
			return "", fmt.Errorf("variable %s has no type information, was the ELF built without BTF?", n)
		}

		// Skip variables that don't have the requested kind.
		tags := v.Type().Tags
		if !slices.Contains(tags, kind) {
			continue
		}

		// Pop the kind tag from the list of tags, we don't want to render it out
		// to the config struct.
		tags = slices.DeleteFunc(tags, func(s string) bool { return s == kind })

		if len(tags) == 0 || tags[0] == "" {
			return "", fmt.Errorf("variable %s has no doc comment", n)
		}

		typ, err := btfGoType(v.Type().Type)
		if err != nil {
			return "", fmt.Errorf("variable %s: getting Go type: %w", n, err)
		}

		comment, err := tagsToComment(tags)
		if err != nil {
			return "", fmt.Errorf("variable %s: converting tags to comments: %w", n, err)
		}

		defValue, err := varGoValue(v)
		if err != nil {
			return "", fmt.Errorf("variable %s: getting default Go value: %w", n, err)
		}

		fields = append(fields, field{comment, camelCase(n), n, typ.String(), goValueLiteral(defValue)})
	}

	slices.SortStableFunc(fields, func(a, b field) int {
		return strings.Compare(a.goName, b.goName)
	})

	var b strings.Builder

	// Render a Go type definition for a configuration struct.
	if comment != "" {
		b.WriteString(wrapString(comment, "// "))
	}
	b.WriteString(fmt.Sprintf("type %s struct {\n", name))

	for _, f := range fields {
		b.WriteString(f.comment)
		b.WriteString(fmt.Sprintf("\t%s %s `%s:\"%s\"`\n", f.goName, f.typ, config.TagName, f.cName))
	}

	if len(embeds) > 0 {
		if len(fields) > 0 {
			b.WriteString("\n")
		}
		for _, e := range embeds {
			b.WriteString(fmt.Sprintf("\t%s\n", e))
		}
	}
	b.WriteString("}\n")

	// Render a constructor with default values set using ASSIGN_CONFIG.
	var params []string
	for _, e := range embeds {
		params = append(params, fmt.Sprintf("%s %s", strings.ToLower(e), e))
	}

	b.WriteString(fmt.Sprintf("\nfunc New%s(%s) *%s {\n", name, strings.Join(params, ", "), name))
	b.WriteString(fmt.Sprintf("\treturn &%s{", name))
	var vals []string
	for _, f := range fields {
		vals = append(vals, f.defValue)
	}
	for _, e := range embeds {
		vals = append(vals, strings.ToLower(e))
	}
	b.WriteString(join(vals))
	b.WriteString("}\n")
	b.WriteString("}\n")

	return b.String(), nil
}

// varGoValue returns the Go value of a variable as an any.
func varGoValue(v *ebpf.VariableSpec) (any, error) {
	typ, err := btfGoType(v.Type().Type)
	if err != nil {
		return nil, fmt.Errorf("getting Go type: %w", err)
	}

	valuePtr := reflect.New(typ).Interface()
	if err := v.Get(valuePtr); err != nil {
		return nil, fmt.Errorf("getting value: %w", err)
	}

	return reflect.ValueOf(valuePtr).Elem().Interface(), nil
}

// camelCase converts a string like "foo_bar" to "FooBar". It capitalizes the
// acronyms defined in 'stylized'.
func camelCase(s string) string {
	var b strings.Builder
	for w := range strings.SplitSeq(s, "_") {
		w = stylize(strings.ToLower(w))
		b.WriteString(cases.Title(language.English, cases.NoLower).String(w))
	}
	return b.String()
}

func stylize(s string) string {
	if v, ok := stylized[s]; ok {
		return v
	}
	return s
}

// tagsToComment converts a slice of tags into a tab-indented string with
// each line prefixed with "//". The first letter of each tag is capitalized
// and a period is added at the end if it doesn't already have one.
func tagsToComment(tags []string) (string, error) {
	var b strings.Builder

	for i, tag := range tags {
		if tag == "" {
			return "", fmt.Errorf("empty tag")
		}

		tag = sentencify(tag)

		// Separate tags by newline comments.
		if i != 0 {
			b.WriteString("\t//\n")
		}

		// Wrap all tags to 80 chars and prefix all lines with //.
		b.WriteString(wrapString(tag, "\t// "))
	}

	return b.String(), nil
}

func wrapString(in, prefix string) string {
	var b strings.Builder
	width := uint(80 - len(prefix))
	for line := range strings.SplitSeq(wordwrap.WrapString(in, width), "\n") {
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// sentencify capitalizes the first letter of a string and adds a period at
// the end if it doesn't already have one.
func sentencify(s string) string {
	if s == "" {
		return ""
	}

	s = strings.ToUpper(s[:1]) + s[1:]
	if s[len(s)-1] != '.' {
		return s + "."
	}

	return s
}

func btfGoType(t btf.Type) (reflect.Type, error) {
	switch t := btf.UnderlyingType(t).(type) {
	case *btf.Int:
		if t.Encoding == btf.Char {
			return reflect.TypeFor[byte](), nil
		}

		if t.Encoding == btf.Bool {
			return reflect.TypeFor[bool](), nil
		}

		if t.Size > 8 {
			return nil, fmt.Errorf("unsupported size %d", t.Size)
		}

		switch t.Size {
		case 1:
			if t.Encoding == btf.Unsigned {
				return reflect.TypeFor[uint8](), nil
			}
			return reflect.TypeFor[int8](), nil
		case 2:
			if t.Encoding == btf.Unsigned {
				return reflect.TypeFor[uint16](), nil
			}
			return reflect.TypeFor[int16](), nil
		case 4:
			if t.Encoding == btf.Unsigned {
				return reflect.TypeFor[uint32](), nil
			}
			return reflect.TypeFor[int32](), nil
		case 8:
			if t.Encoding == btf.Unsigned {
				return reflect.TypeFor[uint64](), nil
			}
			return reflect.TypeFor[int64](), nil
		default:
			return nil, fmt.Errorf("unsupported size %d", t.Size)
		}

	case *btf.Union:
		// Unions can't be represented in Go and are most often used for accessing
		// subfields of addresses. Emit a fixed-size byte array instead.
		return reflect.ArrayOf(int(t.Size), reflect.TypeFor[byte]()), nil

	case *btf.Array:
		sub, err := btfGoType(t.Type)
		if err != nil {
			return nil, fmt.Errorf("array type %v: %w", t.Type, err)
		}
		if t.Nelems <= 0 {
			return nil, fmt.Errorf("array with non-positive number of elements %d", t.Nelems)
		}
		return reflect.ArrayOf(int(t.Nelems), sub), nil

	case *btf.Struct:
		var structFields []reflect.StructField
		paddingFieldCount := 0
		for i, field := range t.Members {
			if field.Name == "" {
				return nil, fmt.Errorf("struct field with no name")
			}

			fieldType, err := btfGoType(field.Type)
			if err != nil {
				return nil, fmt.Errorf("struct field %s: %w", field.Name, err)
			}

			structFields = append(structFields, reflect.StructField{
				Name: camelCase(field.Name),
				Type: fieldType,
			})

			var next int
			if i+1 < len(t.Members) {
				next = int(t.Members[i+1].Offset / 8)
			} else {
				// If this is the last field, use the size of the struct to determine
				// the padding.
				next = int(t.Size)
			}

			fieldSize, err := btf.Sizeof(field.Type)
			if err != nil {
				return nil, fmt.Errorf("struct field %s: getting size: %w", field.Name, err)
			}

			paddingSize := next - (int(field.Offset/8) + fieldSize)
			if paddingSize > 0 {
				structFields = append(structFields, reflect.StructField{
					Name: fmt.Sprintf("Pad%d", paddingFieldCount),
					Type: reflect.ArrayOf(int(paddingSize), reflect.TypeFor[byte]()),
				})
				paddingFieldCount++
			}
		}

		return reflect.StructOf(structFields), nil
	}

	return nil, fmt.Errorf("unsupported type %T", t)
}

// goValueLiteral returns a string representation of a Go value.
func goValueLiteral(v any) string {
	str := fmt.Sprintf("%#v", v)
	switch t := v.(type) {
	case []byte:
		// Replace a slice literal with a fixed-size array literal. Since we can't
		// create arrays of a given size at runtime to feed to fmt.Sprintf(), do a
		// manual conversion.
		str = strings.Replace(str, "[]byte{", fmt.Sprintf("[%d]byte{", len(t)), 1)
	}
	return str
}

// join joins a slice of strings into a comma-separated string, wrapping lines
// and indenting with two tabs.
func join(vars []string) string {
	// Chosen to roughly fit "return &BPFFoo{" and some defaults on the first line.
	const maxLen = 60

	var out bytes.Buffer
	var line bytes.Buffer

	for i, s := range vars {
		line.WriteString(s)
		if i == len(vars)-1 {
			// Last entry, no further output.
			break
		}

		// Not the last entry, write a comma.
		line.WriteString(",")

		if line.Len() > maxLen || len(vars[i+1]) > maxLen {
			// If the current line or the next entry are too long, flush the line and
			// write a newline.
			out.Write(line.Bytes())
			line.Reset()

			line.WriteString("\n\t\t")
		} else {
			// Otherwise, separate entries with a space.
			line.WriteString(" ")
		}
	}

	out.Write(line.Bytes())

	return out.String()
}
