package secrets

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const phoneValueLimit = 64 * 1024
const phoneWireLimit = 512 * 1024
const phoneBatchCapability = "inject_batch_v1"

var unsupportedPhoneTemplate = errors.New("unsupported_template")
var invalidPhoneBatch = errors.New("invalid_batch")
var phoneOutputLimit = errors.New("output_limit")

type phoneField struct {
	ID          string `json:"id"`
	Vault       string `json:"vault"`
	Item        string `json:"item"`
	Field       string `json:"field"`
	Occurrences int    `json:"occurrences"`
}

// Only the parser constructs these parts. Literals borrow the owned template
// buffer; references use indices into fields, never raw expressions.
type phonePart struct {
	literal []byte
	field   int // -1 denotes a literal
}
type phoneTemplate struct {
	input        []byte
	parts        []phonePart
	fields       []phoneField
	literalBytes int
	occurrences  int
}

func parsePhoneTemplate(input []byte) (*phoneTemplate, error) {
	if len(input) > MaxRequest || !utf8.Valid(input) || bytes.IndexByte(input, 0) >= 0 {
		return nil, unsupportedPhoneTemplate
	}
	t := &phoneTemplate{input: bytes.Clone(input)}
	ok := false
	defer func() {
		if !ok {
			t.clear()
		}
	}()
	seen := map[string]int{}
	start := 0
	for i := 0; i < len(t.input); {
		if t.input[i] == '$' && i+1 < len(t.input) {
			n := t.input[i+1]
			if n == '{' || n == '_' || n >= 'a' && n <= 'z' || n >= 'A' && n <= 'Z' {
				return nil, unsupportedPhoneTemplate
			}
		}
		if bytes.HasPrefix(t.input[i:], []byte("}}")) {
			return nil, unsupportedPhoneTemplate
		}
		if !bytes.HasPrefix(t.input[i:], []byte("{{")) {
			i++
			continue
		}
		if i > start {
			t.parts = append(t.parts, phonePart{literal: t.input[start:i], field: -1})
			t.literalBytes += i - start
		}
		end := bytes.Index(t.input[i+2:], []byte("}}"))
		if end < 0 {
			return nil, unsupportedPhoneTemplate
		}
		end += i + 2
		expr := strings.Trim(string(t.input[i+2:end]), " \t\r\n\v\f")
		path, found := strings.CutPrefix(expr, "op://")
		if !found {
			return nil, unsupportedPhoneTemplate
		}
		components := strings.Split(path, "/")
		if len(components) != 3 && len(components) != 4 {
			return nil, unsupportedPhoneTemplate
		}
		for _, c := range components {
			if c == "" || strings.TrimSpace(c) != c || strings.ContainsAny(c, "?&#%\\${}") {
				return nil, unsupportedPhoneTemplate
			}
			for _, r := range c {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					return nil, unsupportedPhoneTemplate
				}
			}
		}
		index, found := seen[path]
		if !found {
			index = len(t.fields)
			seen[path] = index
			t.fields = append(t.fields, phoneField{ID: "f" + strconv.Itoa(index+1), Vault: components[0], Item: components[1], Field: strings.Join(components[2:], "/")})
		}
		t.fields[index].Occurrences++
		t.occurrences++
		t.parts = append(t.parts, phonePart{field: index})
		i = end + 2
		start = i
	}
	if start < len(t.input) {
		t.parts = append(t.parts, phonePart{literal: t.input[start:], field: -1})
		t.literalBytes += len(t.input) - start
	}
	ok = true
	return t, nil
}

func (t *phoneTemplate) clear() {
	clear(t.input)
	t.input = nil
	t.parts = nil
	t.fields = nil
}

type phoneBatchValue struct {
	ID    string  `json:"id"`
	Value *string `json:"value"` // nil is missing/null; a pointer to "" is explicit empty
}

// A complete batch can only be constructed against a parsed template. This is
// transient owned storage, never a partial backend draft or a retry buffer.
type completePhoneBatch struct {
	values [][]byte
	size   int
}

func (t *phoneTemplate) complete(values []phoneBatchValue) (*completePhoneBatch, error) {
	if len(values) != len(t.fields) {
		return nil, invalidPhoneBatch
	}
	indices := make(map[string]int, len(t.fields))
	for i, f := range t.fields {
		indices[f.ID] = i
	}
	selected := make([]bool, len(t.fields))
	b := &completePhoneBatch{values: make([][]byte, len(t.fields)), size: t.literalBytes}
	ok := false
	defer func() {
		if !ok {
			b.clear()
		}
	}()
	for _, value := range values {
		i, found := indices[value.ID]
		if !found || selected[i] || value.Value == nil || !utf8.ValidString(*value.Value) || len(*value.Value) > phoneValueLimit {
			return nil, invalidPhoneBatch
		}
		selected[i] = true
		b.values[i] = []byte(*value.Value)
		// Account for repeats before allocating any rendered output.
		b.size += len(b.values[i]) * t.fields[i].Occurrences
	}
	if b.size > MaxOutput {
		return nil, phoneOutputLimit
	}
	ok = true
	return b, nil
}
func (b *completePhoneBatch) clear() {
	for _, value := range b.values {
		clear(value)
	}
	b.values = nil
}
func (t *phoneTemplate) render(ctx context.Context, b *completePhoneBatch) ([]byte, error) {
	output := make([]byte, 0, b.size)
	for _, part := range t.parts {
		if err := ctx.Err(); err != nil {
			clear(output)
			return nil, err
		}
		if part.field < 0 {
			output = append(output, part.literal...)
		} else {
			output = append(output, b.values[part.field]...)
		}
	}
	if err := ctx.Err(); err != nil {
		clear(output)
		return nil, err
	}
	return output, nil
}
