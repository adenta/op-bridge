package secrets

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func batchValues(tmpl *phoneTemplate, values ...string) []phoneBatchValue {
	out := make([]phoneBatchValue, len(values))
	for i := range values {
		value := values[i]
		out[i] = phoneBatchValue{ID: tmpl.fields[i].ID, Value: &value}
	}
	return out
}
func TestPhoneTemplateParsedPartsAndCompleteBatch(t *testing.T) {
	input := "head\n{{ op://Vault/Some item/password }}:{{op://Vault/Some item/password}}\n{{\top://另一个/Item/Section/field\n}}\n"
	tmpl, err := parsePhoneTemplate([]byte(input))
	if err != nil {
		t.Fatal("supported template rejected")
	}
	defer tmpl.clear()
	if len(tmpl.fields) != 2 || tmpl.occurrences != 3 || tmpl.fields[0].Occurrences != 2 || tmpl.fields[1].Field != "Section/field" {
		t.Fatal("incorrect grouping")
	}
	values := batchValues(tmpl, "{{ op://not/recursively/resolved }}\n$NAME", "")
	b, err := tmpl.complete(values)
	if err != nil {
		t.Fatal("complete batch rejected")
	}
	defer b.clear()
	output, err := tmpl.render(context.Background(), b)
	if err != nil {
		t.Fatal("render failed")
	}
	defer clear(output)
	want := "head\n" + *values[0].Value + ":" + *values[0].Value + "\n\n"
	if !bytes.Equal(output, []byte(want)) {
		t.Fatal("literal substitution differed")
	}
	for _, input := range []string{"", "literal\r\n{} $5", "{{op://v/i/f}}{{op://v/i/F}}"} {
		p, err := parsePhoneTemplate([]byte(input))
		if err != nil {
			t.Fatal("supported input rejected")
		}
		p.clear()
	}
}
func TestPhoneTemplateRejectsEntireUnsupportedInput(t *testing.T) {
	invalid := []string{"{{op://v/i/f}} {{op://v//f}}", "{{op://v/i/f}", "}}", "{{}}", "{{ other }}", "{{op://v/i/{{f}}}}", "{{op://v/i/f/a/b}}", "{{op://v/i/f?attribute=otp}}", "{{op://v/i/f%20}}", "{{op://v/i/f#x}}", "{{op://v/i/f&x}}", "{{op://v/i/f\\x}}", "{{op://v/ i/f}}", "{{op://v/i /f}}", "{{op://v/i/\u200ef}}", "{{op://v/i/line\nf}}", "$NAME", "${NAME}", "prefix\x00suffix", string([]byte{0xff})}
	for i, input := range invalid {
		tmpl, err := parsePhoneTemplate([]byte(input))
		if err != unsupportedPhoneTemplate || tmpl != nil {
			t.Fatalf("unsupported case %d accepted", i)
		}
	}
	if _, err := parsePhoneTemplate(bytes.Repeat([]byte("x"), MaxRequest+1)); err == nil {
		t.Fatal("large template accepted")
	}
}
func TestPhoneCompleteBatchRejectsMissingDuplicateAndUnknownValues(t *testing.T) {
	tmpl, _ := parsePhoneTemplate([]byte("{{op://v/i/a}}{{op://v/i/b}}"))
	defer tmpl.clear()
	valid := batchValues(tmpl, "first", "second")
	unknown := append([]phoneBatchValue(nil), valid...)
	unknown[1].ID = "unknown"
	missing := append([]phoneBatchValue(nil), valid...)
	missing[1].Value = nil
	oversized := batchValues(tmpl, strings.Repeat("x", phoneValueLimit+1), "")
	invalidUTF8 := batchValues(tmpl, string([]byte{0xff}), "")
	for _, values := range [][]phoneBatchValue{nil, valid[:1], append(valid, valid[0]), {valid[0], valid[0]}, unknown, missing, oversized, invalidUTF8} {
		batch, err := tmpl.complete(values)
		if err != invalidPhoneBatch || batch != nil {
			t.Fatal("incomplete/invalid batch accepted")
		}
	}
	b, err := tmpl.complete(batchValues(tmpl, "", strings.Repeat("x", phoneValueLimit)))
	if err != nil {
		t.Fatal("boundary value rejected")
	}
	b.clear()
}
func TestPhoneRenderLimitsCancellationAndBufferClearing(t *testing.T) {
	for _, extra := range []string{"", "x"} {
		tmpl, err := parsePhoneTemplate([]byte(strings.Repeat("{{op://v/i/f}}", 256) + extra))
		if err != nil {
			t.Fatal("template rejected")
		}
		b, err := tmpl.complete(batchValues(tmpl, strings.Repeat("x", phoneValueLimit)))
		if extra != "" {
			if err != phoneOutputLimit || b != nil {
				t.Fatal("oversized expansion accepted")
			}
			tmpl.clear()
			continue
		}
		if err != nil || b.size != MaxOutput {
			t.Fatal("exact output limit rejected")
		}
		output, err := tmpl.render(context.Background(), b)
		if err != nil || len(output) != MaxOutput {
			t.Fatal("exact output limit rendering failed")
		}
		clear(output)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if output, err := tmpl.render(ctx, b); err == nil || output != nil {
			t.Fatal("cancelled render returned output")
		}
		selected := b.values[0]
		original := tmpl.input
		b.clear()
		tmpl.clear()
		if !bytes.Equal(selected, make([]byte, len(selected))) || !bytes.Equal(original, make([]byte, len(original))) {
			t.Fatal("owned secret buffers not cleared")
		}
	}
}
