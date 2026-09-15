package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandaloneExamples(t *testing.T) {
	for _, name := range []string{"desktop", "client", "owner-only"} {
		data, err := os.ReadFile("../../deploy/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		c, err := decodeConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := selectRoute(c, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfigurationRejectsAmbiguousAndUnsafeInput(t *testing.T) {
	base, _ := json.Marshal(routingConfig(t, "laptop"))
	for _, input := range []string{
		string(base) + ` {}`, string(base) + ` garbage`, `null`, `{}`,
		strings.Replace(string(base), `"version":3`, `"version":3,"version":3`, 1),
		strings.Replace(string(base), `"machine":`, `"unknown":true,"machine":`, 1),
		strings.Repeat(" ", MaxRequest) + string(base),
	} {
		if _, err := decodeConfig(strings.NewReader(input)); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Local.Owner = "root" },
		func(c *Config) { c.Local.Owner = "1234" },
		func(c *Config) { c.Local.Owner = "a';touch /tmp/no;#" },
		func(c *Config) { c.Local.Caller = "ALL"; c.Local.Owner = "ALL" },
		func(c *Config) { c.Local.Account = "other.1password.com" },
		func(c *Config) { c.Local.Account = "team.1password.com\nOP_DEBUG=true" },
		func(c *Config) {
			d := c.Desktops["workstation"]
			d.SSHHost = "-oProxyCommand=evil"
			c.Desktops["workstation"] = d
		},
		func(c *Config) { d := c.Desktops["workstation"]; d.SSHHost = "host;id"; c.Desktops["workstation"] = d },
		func(c *Config) { d := c.Desktops["workstation"]; d.Owner = "bob'"; c.Desktops["workstation"] = d },
		func(c *Config) { d := c.Desktops["workstation"]; d.Transport = "auto"; c.Desktops["workstation"] = d },
	} {
		c := routingConfig(t, "laptop")
		change(&c)
		if validateConfig(c) == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestClientCarriesAccountAndDesktopRejectsMismatch(t *testing.T) {
	c := routingConfig(t, "builder")
	var out, stderr bytes.Buffer
	for _, args := range [][]string{{"vault", "list"}, {"item", "create", "-"}} {
		calls := 0
		code := runClient(c, args, strings.NewReader(`{"title":"fake"}`), &out, &stderr, func(_ context.Context, _ Config, _ Route, r Request) Response {
			calls++
			if !strings.Contains(strings.Join(r.Args, " "), "--account="+testPolicy.Account) {
				t.Fatal("request lost account pin")
			}
			data, _ := json.Marshal(r)
			if _, err := decodeRequest(bytes.NewReader(data), Policy{Account: "different.1password.eu"}); err == nil {
				t.Fatal("desktop accepted a different account")
			}
			if _, err := decodeRequest(bytes.NewReader(data), testPolicy); err != nil {
				t.Fatal(err)
			}
			return Response{Version: Protocol}
		})
		if code != 0 || calls != 1 {
			t.Fatal("valid request did not dispatch")
		}
	}
	code := runClient(c, []string{"vault", "list", "--account=other.1password.com"}, nil, &out, &stderr, func(context.Context, Config, Route, Request) Response {
		t.Fatal("account override dispatched")
		return Response{}
	})
	if code == 0 {
		t.Fatal("account override accepted")
	}
}

func TestDesktopRejectsAccountBeforeNotification(t *testing.T) {
	w := testWorker(t, "echo should-not-run\n")
	p := testSessionPolicy(w, workerLifetime)
	p.notify = func(context.Context, Request) error { t.Error("invalid account notified"); return nil }
	socket := testSession(t, p)
	r := writeRequest()
	r.Args = append(r.Args, "--account=other.1password.com")
	response := sessionCall(t, socket, r)
	if response.Exit == 0 || len(response.Stdout) != 0 || !response.NotStarted {
		t.Fatal("invalid account executed")
	}
}

func TestWorkerIndependentlyEnforcesAccount(t *testing.T) {
	w := testWorker(t, "echo should-not-run\n")
	r := readRequest()
	r.Args = append(r.Args, "--account=other.1password.com")
	if _, err := w.send(r); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := w.decoder.Decode(&response); err == nil {
		t.Fatal("worker accepted another account")
	}
}

func TestDesktopEnvironmentAndPaths(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "fake-must-not-propagate")
	t.Setenv("OP_ACCOUNT", "wrong.1password.com")
	u := &user.User{Username: "alice", Uid: "1234", HomeDir: "/home/alice"}
	env := strings.Join(desktopEnv(u, testPolicy), "\n")
	if strings.Contains(env, "fake-must-not-propagate") || strings.Contains(env, "wrong.") || !strings.Contains(env, "OP_ACCOUNT="+testPolicy.Account) {
		t.Fatal("caller environment entered native CLI")
	}
	if historyPath(u) != "/home/alice/.local/state/op-bridge/history" {
		t.Fatal("history still depends on Ops layout")
	}
	d, s := runtimePaths(u)
	if d != "/run/user/1234/op-bridge" || s != d+"/session.sock" {
		t.Fatal("incorrect runtime path")
	}
}

func TestStagedConfigAndSudoRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(routingConfig(t, "laptop"))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if handled, code := configCommand([]string{"config", "check", path}, &out, &stderr); !handled || code != 0 {
		t.Fatal(stderr.String())
	}
	out.Reset()
	if _, code := configCommand([]string{"config", "sudoers", path}, &out, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	want := "automation ALL=(alice) NOPASSWD: NOSETENV: " + InstalledBinary + " _bridge\n"
	if !strings.HasSuffix(out.String(), want) || strings.Contains(out.String(), "ALL=(ALL)") {
		t.Fatal("unexpected sudo grant")
	}
	sudoers := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(sudoers, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		t.Skip("visudo unavailable; run bin/check-package before release")
	}
	if output, err := exec.Command(visudo, "-cf", sudoers).CombinedOutput(); err != nil {
		t.Fatalf("visudo: %s %v", output, err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if os.Geteuid() != 0 && trustedConfigFile(f) == nil {
		t.Fatal("non-root runtime policy accepted")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if trustedConfigFile(f) == nil {
		t.Fatal("writable runtime policy accepted")
	}
}
