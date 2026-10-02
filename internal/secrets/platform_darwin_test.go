//go:build darwin && arm64

package secrets

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDarwinPlatformPolicy(t *testing.T) {
	u := &user.User{Username: "alice", Uid: "501", HomeDir: "/Users/alice"}
	dir, socket := runtimePaths(u)
	if opBinary != "/opt/homebrew/bin/op" || dir != "/Users/alice/Library/Caches/op-bridge" || socket != dir+"/session.sock" {
		t.Fatalf("unexpected Darwin paths: %q %q %q", opBinary, dir, socket)
	}
	target, err := launchAgentTarget(u)
	if err != nil || target != "gui/501/"+launchAgentLabel {
		t.Fatalf("unexpected launch target: %q %v", target, err)
	}
	env := strings.Join(desktopEnv(u, testPolicy), "\n")
	for _, want := range []string{"HOME=/Users/alice", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "OP_ACCOUNT=" + testPolicy.Account, "OP_CACHE=false"} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing environment %q: %s", want, env)
		}
	}
}

func TestDarwinRuntimeParentValidation(t *testing.T) {
	home := t.TempDir()
	uid := strconv.Itoa(os.Geteuid())
	u := &user.User{Username: "alice", Uid: uid, HomeDir: home}
	for _, path := range []string{filepath.Join(home, "Library"), filepath.Join(home, "Library", "Caches")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeParent(u); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, "Library", "Caches"), 0770); err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeParent(u); err == nil {
		t.Fatal("group-writable cache parent accepted")
	}
}

func TestDarwinDoctorRequiresTerminalChecks(t *testing.T) {
	checks := map[string]any{
		"gui_domain_available": true, "launch_agent_registered": true,
		"terminal_available": true, "terminal_launcher_trusted": true,
	}
	if !platformDoctorOK(checks) {
		t.Fatal("valid checks rejected")
	}
	for name := range checks {
		checks[name] = false
		if platformDoctorOK(checks) {
			t.Fatalf("missing prerequisite accepted: %s", name)
		}
		checks[name] = true
	}
}
