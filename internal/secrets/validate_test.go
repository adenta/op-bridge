package secrets

import (
	"reflect"
	"strings"
	"testing"
)

var testPolicy = Policy{Account: "example.1password.com"}

func TestConfiguredAccounts(t *testing.T) {
	for _, account := range []string{"my.1password.com", "team.1password.eu", "work.1password.ca"} {
		p := Policy{Account: account}
		r := Request{Version: Protocol, Action: "read", Args: []string{"vault", "list"}}
		argv, err := p.Validate(r)
		if err != nil || !reflect.DeepEqual(argv, []string{"vault", "list", "--account=" + account}) {
			t.Fatalf("configured account not pinned: %v %v", argv, err)
		}
	}
	if _, err := (Policy{}).Validate(Request{Version: Protocol, Action: "status"}); err == nil {
		t.Fatal("missing policy must not imply a default account")
	}
}

func TestCommandBoundary(t *testing.T) {
	allowed := [][]string{
		{"vault", "list", "--format=json"},
		{"item", "list", "--vault", "My Vault", "--tags=a,b"},
		{"item", "get", "literal;$(touch /tmp/no)", "--fields", "password"},
		{"read", "op://Vault/Item/password", "--no-newline"},
		{"item", "get", "id", "--otp", "--account=" + testPolicy.Account},
	}
	for _, args := range allowed {
		got, err := testPolicy.Validate(Request{Version: Protocol, Action: "read", Args: args})
		if err != nil || !strings.Contains(strings.Join(got, " "), "--account="+testPolicy.Account) {
			t.Fatalf("allowed command failed: %v: %v", args, err)
		}
	}
	denied := [][]string{
		{"run", "--", "sh"}, {"exec", "sh"}, {"signin"}, {"item", "create"},
		{"item", "delete", "id"}, {"item", "get", "-"}, {"item", "get", "--", "id"},
		{"read", "op://v/i/f", "--out=/tmp/secret"}, {"read", "/etc/shadow"},
		{"read", "op://v/i/f", "--config=/tmp/config"},
		{"item", "get", "id", "--account=other.1password.com"},
		{"item", "get", "id", "--fields", "--account=bad"},
		{"item", "get", "id\n"}, {"vault", "list", "--debug"},
		{"item", "get", "id", "--format=csv"}, {"document", "get", "id"},
	}
	for _, args := range denied {
		if _, err := testPolicy.Validate(Request{Version: Protocol, Action: "read", Args: args}); err == nil {
			t.Fatalf("unsafe command accepted: %v", args)
		}
	}
	got, _ := testPolicy.Validate(Request{Version: Protocol, Action: "read", Args: []string{"item", "get", "id", "--fields", "password"}})
	want := []string{"item", "get", "--account=" + testPolicy.Account, "--fields=password", "id"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %v", got)
	}
	for _, r := range []Request{{Version: Protocol + 1, Action: "status"}, {Version: Protocol, Action: "stop", Args: []string{"sh"}}, {Version: Protocol, Action: "status", Timeout: 301}} {
		if _, err := testPolicy.Validate(r); err == nil {
			t.Fatal("invalid protocol request accepted")
		}
	}
}

func writeRequest() Request {
	return Request{Version: Protocol, Action: "write", Args: []string{"item", "create", "--vault", "Test", "-"}, Stdin: []byte(`{"category":"SECURE_NOTE","title":"test","fields":[{"id":"key","type":"CONCEALED","value":"fake line 1\nfake line 2\n"}]}`)}
}

func TestWriteBoundary(t *testing.T) {
	for _, args := range [][]string{
		{"item", "create", "--vault", "Test", "-", "--format=json", "--dry-run"},
		{"item", "edit", "item-id", "--vault=Test", "--format", "human-readable", "--dry-run"},
	} {
		r := writeRequest()
		r.Args = args
		got, err := testPolicy.Validate(r)
		if err != nil || !strings.Contains(strings.Join(got, " "), "--account="+testPolicy.Account) {
			t.Fatalf("write rejected: %v", err)
		}
	}
	for _, args := range [][]string{
		{"item", "create", "--template", "/etc/shadow", "-"},
		{"item", "create", "file[file]=/etc/shadow"},
		{"item", "edit", "item-id", "password=value"},
		{"item", "edit", "item-id", "--out-file=/tmp/output"},
		{"item", "edit", "-"},
		{"item", "create", "-", "--account=other"},
		{"item", "delete", "item-id"}, {"run", "--", "sh"}, {"exec", "sh"},
		{"document", "create", "-"},
	} {
		r := writeRequest()
		r.Args = args
		if _, err := testPolicy.Validate(r); err == nil {
			t.Fatalf("unsupported write accepted: %v", args)
		}
	}
	for _, input := range []string{"", " ", "null", "[]", "{}", "{invalid", `{"title":"ok"} {}`, `{"fields":[{"type":"FILE","value":"/etc/shadow"}]}`, `{"files":[{"id":"attachment"}]}`, `{"category":"DOCUMENT"}`} {
		r := writeRequest()
		r.Stdin = []byte(input)
		if _, err := testPolicy.Validate(r); err == nil {
			t.Fatal("unsupported input accepted")
		}
	}
	r := writeRequest()
	r.Stdin = []byte(`{"title":"` + strings.Repeat("x", MaxRequest*3/4) + `"}`)
	if _, err := testPolicy.Validate(r); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatal("encoded request limit not enforced")
	}
	r = writeRequest()
	r.Action = "read"
	if _, err := testPolicy.Validate(r); err == nil {
		t.Fatal("write accepted as read")
	}
	r.Action, r.Args = "status", nil
	if _, err := testPolicy.Validate(r); err == nil {
		t.Fatal("input accepted on control request")
	}
}
