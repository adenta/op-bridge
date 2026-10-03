package secrets

import (
	"fmt"
	"strings"
	"unicode"
)

type phoneSelection struct {
	Account string `json:"account"`
	Vault   string `json:"vault"`
	Item    string `json:"item"`
	Field   string `json:"field"`
	Newline bool   `json:"-"`
}

// Phone reads are manually selected values, never verified native CLI lookups.
func phoneRead(p Policy, r Request) (phoneSelection, error) {
	out := phoneSelection{Account: p.Account, Newline: true}
	unsupported := fmt.Errorf("unsupported_operation: phone destination supports only a single plain-text field; use a desktop destination")
	if r.Action != "read" {
		return out, unsupported
	}
	args, err := p.Validate(r)
	if err != nil {
		return out, err
	}
	n := 1
	read := args[0] == "read"
	if !read {
		if len(args) < 2 || args[0] != "item" || args[1] != "get" {
			return out, unsupported
		}
		n = 2
	}
	var positional string
	seen := map[string]bool{}
	for _, a := range args[n:] {
		if !strings.HasPrefix(a, "-") {
			positional = a
			continue
		}
		key, val, _ := strings.Cut(a, "=")
		if seen[key] {
			return out, unsupported
		}
		seen[key] = true
		switch key {
		case "--account":
		case "-n", "--no-newline":
			if !read {
				return out, unsupported
			}
			out.Newline = false
		case "--vault":
			if read {
				return out, unsupported
			}
			out.Vault = val
		case "--fields":
			if read || strings.ContainsAny(val, ",=") {
				return out, unsupported
			}
			out.Field = val
		case "--reveal":
			if read {
				return out, unsupported
			}
		case "--format":
			if read || val != "human-readable" {
				return out, unsupported
			}
		default:
			return out, unsupported
		}
	}
	if read {
		parts := strings.Split(strings.TrimPrefix(positional, "op://"), "/")
		if len(parts) != 3 && len(parts) != 4 {
			return out, unsupported
		}
		out.Vault, out.Item = parts[0], parts[1]
		out.Field = strings.Join(parts[2:], "/")
		for _, part := range parts {
			if part == "" {
				return out, unsupported
			}
		}
	} else {
		out.Item = positional
		if out.Field == "" {
			return out, unsupported
		}
	}
	for _, value := range []string{out.Vault, out.Item, out.Field} {
		if strings.ContainsAny(value, "?&#%") {
			return out, unsupported
		}
		for _, char := range value {
			if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
				return out, unsupported
			}
		}
	}
	return out, nil
}
