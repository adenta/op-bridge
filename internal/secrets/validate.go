package secrets

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Policy is loaded from the administrator-owned configuration, never the request.
type Policy struct{ Account string }

const Protocol = 2
const ConfigVersion = 3
const MaxOutput = 16 << 20
const MaxRequest = 64 << 10

// JSON encodes the two byte streams as base64.
const MaxResponse = 2*((MaxOutput+2)/3*4) + MaxRequest

type Request struct {
	Version int      `json:"version"`
	Action  string   `json:"action"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout_seconds,omitempty"`
	Stdin   []byte   `json:"stdin,omitempty"`
}

type Response struct {
	Version int    `json:"version"`
	Stdout  []byte `json:"stdout,omitempty"`
	Stderr  []byte `json:"stderr,omitempty"`
	Exit    int    `json:"exit"`
	Error   string `json:"error,omitempty"`
	// Set only when the operation is known not to have reached the native CLI.
	NotStarted bool `json:"not_started,omitempty"`
}

func failure(message string) Response { return Response{Version: Protocol, Exit: 1, Error: message} }

func notStarted(message string) Response {
	r := failure(message)
	r.NotStarted = true
	return r
}

func writeCommand(args []string) bool {
	return len(args) >= 2 && args[0] == "item" && (args[1] == "create" || args[1] == "edit")
}

// Keep errors free of template contents. Native op validates the item schema.
func validateTemplate(input []byte) error {
	var item map[string]any
	if json.Unmarshal(input, &item) != nil || len(item) == 0 {
		return fmt.Errorf("writes require a nonempty JSON item object on standard input")
	}
	var hasFile func(any) bool
	hasFile = func(value any) bool {
		switch v := value.(type) {
		case map[string]any:
			for k, child := range v {
				if strings.EqualFold(k, "type") && strings.EqualFold(fmt.Sprint(child), "file") {
					return true
				}
				if strings.EqualFold(k, "files") || strings.EqualFold(k, "document") || strings.EqualFold(k, "attachments") {
					if child != nil {
						if a, ok := child.([]any); !ok || len(a) != 0 {
							return true
						}
					}
				}
				if hasFile(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if hasFile(child) {
					return true
				}
			}
		}
		return false
	}
	if hasFile(item) || strings.EqualFold(fmt.Sprint(item["category"]), "document") {
		return fmt.Errorf("file attachments and document templates are not supported")
	}
	return nil
}

// Validate is applied on both sides of the user boundary. It reconstructs argv;
// caller input is never interpreted by a shell or accepted as global op flags.
func (p Policy) Validate(r Request) ([]string, error) {
	if !validAccount(p.Account) {
		return nil, fmt.Errorf("invalid configured account")
	}
	if r.Version != Protocol {
		return nil, fmt.Errorf("protocol mismatch; update op-bridge on both hosts")
	}
	if len(r.Stdin) > MaxRequest {
		return nil, fmt.Errorf("request exceeds the 64 KiB limit")
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded)+1 > MaxRequest {
		return nil, fmt.Errorf("request exceeds the 64 KiB limit")
	}
	if r.Timeout < 0 || r.Timeout > 300 {
		return nil, fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	if r.Action != "read" && r.Action != "write" {
		if (r.Action == "status" || r.Action == "doctor" || r.Action == "stop") && len(r.Args) == 0 && len(r.Stdin) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("unsupported request")
	}
	if (r.Action == "write") != writeCommand(r.Args) || (r.Action == "read" && len(r.Stdin) != 0) {
		return nil, fmt.Errorf("command and request action do not match")
	}
	if r.Action == "write" {
		if err := validateTemplate(r.Stdin); err != nil {
			return nil, err
		}
	}
	if len(r.Args) == 0 || len(r.Args) > 64 {
		return nil, fmt.Errorf("invalid command")
	}
	for _, a := range r.Args {
		if len(a) > 4096 || strings.ContainsAny(a, "\x00\r\n") {
			return nil, fmt.Errorf("invalid argument")
		}
	}
	n := 2
	var operation string
	if r.Args[0] == "read" {
		operation, n = "read", 1
	} else if len(r.Args) >= 2 {
		operation = strings.Join(r.Args[:2], " ")
	}
	values := map[string]bool{}
	switches := map[string]bool{}
	want := 0
	switch operation {
	case "read":
		want = 1
		switches["--no-newline"] = true
		switches["-n"] = true
	case "vault list":
		values["--format"] = true
	case "item list":
		for _, f := range []string{"--format", "--vault", "--tags", "--categories"} {
			values[f] = true
		}
		for _, f := range []string{"--favorite", "--include-archive", "--long"} {
			switches[f] = true
		}
	case "item get":
		want = 1
		for _, f := range []string{"--format", "--vault", "--fields"} {
			values[f] = true
		}
		for _, f := range []string{"--reveal", "--otp", "--include-archive"} {
			switches[f] = true
		}
	case "item create", "item edit":
		want = 1
		values["--vault"] = true
		values["--format"] = true
		switches["--dry-run"] = true
	default:
		return nil, fmt.Errorf("supported commands: vault list, item list, item get, item create, item edit, read")
	}
	values["--account"] = true
	flags, positional := []string{}, []string{}
	for i := n; i < len(r.Args); i++ {
		a := r.Args[i]
		if !strings.HasPrefix(a, "-") || (a == "-" && operation == "item create") {
			positional = append(positional, a)
			continue
		}
		name, value, equals := strings.Cut(a, "=")
		if switches[name] && !equals {
			flags = append(flags, name)
			continue
		}
		if !values[name] {
			return nil, fmt.Errorf("unsupported option: %s", name)
		}
		if !equals {
			i++
			if i == len(r.Args) {
				return nil, fmt.Errorf("missing option value")
			}
			value = r.Args[i]
		}
		if value == "" || strings.HasPrefix(value, "-") {
			return nil, fmt.Errorf("invalid option value")
		}
		if name == "--account" {
			if value != p.Account {
				return nil, fmt.Errorf("only the configured account is permitted")
			}
			continue
		}
		if name == "--format" && value != "json" && value != "human-readable" {
			return nil, fmt.Errorf("unsupported output format")
		}
		flags = append(flags, name+"="+value)
	}
	if len(positional) != want {
		return nil, fmt.Errorf("invalid number of item or reference arguments")
	}
	if operation == "item create" && positional[0] != "-" {
		return nil, fmt.Errorf("item create requires - for JSON input; field assignments are not supported")
	}
	if operation == "read" && (!strings.HasPrefix(positional[0], "op://") || len(strings.Split(strings.TrimPrefix(positional[0], "op://"), "/")) < 3) {
		return nil, fmt.Errorf("read requires an op://vault/item/field reference")
	}
	argv := append([]string{}, r.Args[:n]...)
	argv = append(argv, "--account="+p.Account)
	argv = append(argv, flags...)
	argv = append(argv, positional...)
	return argv, nil
}
