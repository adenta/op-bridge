//go:build linux

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
)

func routingConfig(t *testing.T, host string) Config {
	t.Helper()
	c := Config{Version: ConfigVersion, Machine: host, DefaultDesktop: "laptop", Desktops: map[string]Desktop{
		"laptop":      {Transport: "ssh", SSHHost: "laptop-ssh", Owner: "alice", Account: testPolicy.Account},
		"workstation": {Transport: "ssh", SSHHost: "office-ssh", Owner: "bob", Account: testPolicy.Account},
	}}
	if host != "builder" {
		owner := "alice"
		if host == "workstation" {
			owner = "bob"
		}
		c.Local = &LocalBridge{Owner: owner, Caller: "automation", Account: testPolicy.Account}
		c.Desktops[host] = Desktop{Transport: "local", Account: testPolicy.Account}
	}
	if err := validateConfig(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGeneratedRoutes(t *testing.T) {
	for _, host := range []string{"laptop", "workstation", "builder"} {
		t.Run(host, func(t *testing.T) {
			c := routingConfig(t, host)
			wantDefault := "laptop"
			for _, override := range []string{"", "laptop", "workstation"} {
				route, err := selectRoute(c, override)
				if err != nil {
					t.Fatal(err)
				}
				want, source := wantDefault, "default"
				if override != "" {
					want, source = override, "override"
				}
				transport := "ssh"
				if want == host {
					transport = "local"
				}
				if route != (Route{host, want, transport, source}) {
					t.Fatalf("route=%+v", route)
				}
			}
		})
	}
	c := routingConfig(t, "workstation")
	if c.Local == nil || c.Local.Owner != "bob" || c.DefaultDesktop != "laptop" {
		t.Fatalf("lost local bridge: %+v", c)
	}
	route, _ := selectRoute(routingConfig(t, "laptop"), "workstation")
	args := sshRouteArgs(routingConfig(t, "laptop").Desktops[route.Desktop])
	if args[len(args)-2] != "office-ssh" || args[len(args)-1] != "/usr/bin/sudo -n -u 'bob' "+InstalledBinary+" _bridge" {
		t.Fatalf("remote request must bypass destination default: %v", args)
	}
}

func TestRouteShowDoesNotReadInputOrDispatch(t *testing.T) {
	for _, format := range [][]string{nil, {"--format=json"}, {"--format", "json"}} {
		args := append([]string{"--desktop", "workstation", "route", "show"}, format...)
		var out, stderr bytes.Buffer
		calls := 0
		code := runClient(routingConfig(t, "workstation"), args, forbiddenInput{t}, &out, &stderr, func(context.Context, Config, Route, Request) Response { calls++; return failure("unexpected") })
		if code != 0 || calls != 0 || stderr.Len() != 0 {
			t.Fatalf("code=%d calls=%d stderr=%s", code, calls, &stderr)
		}
		if len(format) > 0 {
			var route Route
			if err := json.Unmarshal(out.Bytes(), &route); err != nil || route != (Route{"workstation", "workstation", "local", "override"}) {
				t.Fatalf("route output=%s error=%v", &out, err)
			}
		} else if !strings.Contains(out.String(), "Approval desktop: workstation") {
			t.Fatal(out.String())
		}
	}
}

type forbiddenInput struct{ t *testing.T }

func (r forbiddenInput) Read([]byte) (int, error) {
	r.t.Fatal("unexpected input read")
	return 0, io.EOF
}

func TestClientRoutingAllOperationsAndFailures(t *testing.T) {
	operations := []struct {
		args          []string
		action, input string
	}{
		{[]string{"read", "op://Vault/Item/field"}, "read", ""},
		{[]string{"vault", "list"}, "read", ""},
		{[]string{"item", "list"}, "read", ""},
		{[]string{"item", "get", "example"}, "read", ""},
		{[]string{"item", "create", "-"}, "write", `{"title":"example","category":"LOGIN"}`},
		{[]string{"item", "edit", "example"}, "write", `{"title":"example"}`},
		{[]string{"session", "doctor"}, "doctor", ""},
		{[]string{"session", "status"}, "status", ""},
		{[]string{"session", "stop"}, "stop", ""},
	}
	for _, op := range operations {
		for _, host := range []string{"laptop", "workstation", "builder"} {
			for _, override := range []string{"", "laptop", "workstation"} {
				for _, fail := range []bool{false, true} {
					var out, stderr bytes.Buffer
					args := []string{"--timeout", "45"}
					if override != "" {
						args = append(args, "--desktop", override)
					}
					args = append(args, op.args...)
					calls := 0
					code := runClient(routingConfig(t, host), args, strings.NewReader(op.input), &out, &stderr, func(_ context.Context, _ Config, route Route, r Request) Response {
						calls++
						wantDesktop := override
						if wantDesktop == "" {
							wantDesktop = "laptop"
						}
						if route.Desktop != wantDesktop || r.Action != op.action || r.Timeout != 45 || string(r.Stdin) != op.input {
							t.Fatalf("route=%+v request=%+v", route, r)
						}
						if fail {
							return failure("SSH unavailable or authorization refused")
						}
						return Response{Version: Protocol, Stdout: []byte("test-value")}
					})
					if calls != 1 || (code != 0) != fail {
						t.Fatalf("%v: code=%d calls=%d stderr=%s", args, code, calls, &stderr)
					}
					if !fail && out.String() != "test-value" {
						t.Fatal("stdout changed")
					}
					if fail && !strings.Contains(stderr.String(), "Desktop ") {
						t.Fatal("missing destination")
					}
					if strings.Contains(stderr.String(), "test-value") || strings.Contains(stderr.String(), "op://") {
						t.Fatal("request data leaked")
					}
				}
			}
		}
	}
}

func TestGlobalOptionsAndInvalidRequests(t *testing.T) {
	for _, args := range [][]string{
		{"--desktop", "workstation", "--timeout", "180", "session", "status"},
		{"--timeout=180", "--desktop=workstation", "session", "status"},
	} {
		rest, desktop, timeout, err := clientOptions(args)
		if err != nil || desktop != "workstation" || timeout != 180 || !reflect.DeepEqual(rest, []string{"session", "status"}) {
			t.Fatalf("options: %v %s %d %v", rest, desktop, timeout, err)
		}
	}
	for _, args := range [][]string{
		{"--desktop", "unknown", "item", "create", "-"},
		{"--desktop", "-oProxyCommand=bad", "session", "status"},
		{"--desktop"}, {"--desktop="}, {"--timeout"}, {"--timeout", "301"},
		{"--timeout", "0"}, {"--timeout", "bad"}, {"--unknown"},
		{"--desktop", "laptop", "--desktop", "workstation", "session", "status"},
		{"route", "show", "--bad"}, {"route"},
	} {
		var out, stderr bytes.Buffer
		code := runClient(routingConfig(t, "workstation"), args, forbiddenInput{t}, &out, &stderr, func(context.Context, Config, Route, Request) Response {
			t.Fatal("invalid request dispatched")
			return Response{}
		})
		if code == 0 {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestRoutingConfigRejectsUnsafeDestinations(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Version = 1 },
		func(c *Config) {
			c.Desktops["bad"] = Desktop{Transport: "ssh", SSHHost: "-oProxyCommand=bad", Owner: "alice", Account: testPolicy.Account}
		},
		func(c *Config) { c.DefaultDesktop = "other" },
		func(c *Config) { c.Machine = "-bad" },
		func(c *Config) { c.Local = nil },
	} {
		c := routingConfig(t, "workstation")
		mutate(&c)
		if validateConfig(c) == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
