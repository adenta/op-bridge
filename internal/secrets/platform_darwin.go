//go:build darwin && arm64

package secrets

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const opBinary = "/opt/homebrew/bin/op"
const launchAgentLabel = "com.adenta.op-bridge.session"
const terminalApp = "/System/Applications/Utilities/Terminal.app"
const terminalLauncher = "/usr/local/libexec/op-bridge/Launch.command"

func desktopEnv(u *user.User, p Policy) []string {
	return []string{
		"HOME=" + u.HomeDir,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LANG=en_US.UTF-8",
		"OP_ACCOUNT=" + p.Account,
		"OP_BIOMETRIC_UNLOCK_ENABLED=true",
		"OP_CACHE=false",
	}
}

func runtimePaths(u *user.User) (string, string) {
	d := filepath.Join(u.HomeDir, "Library", "Caches", "op-bridge")
	return d, filepath.Join(d, "session.sock")
}

func validateRuntimeParent(u *user.User) error {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("desktop owner is unavailable")
	}
	for _, path := range []string{u.HomeDir, filepath.Join(u.HomeDir, "Library"), filepath.Join(u.HomeDir, "Library", "Caches")} {
		s, err := os.Lstat(path)
		if err != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("unsafe desktop cache parent")
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || uint64(st.Uid) != uid {
			return fmt.Errorf("desktop cache parent owner mismatch")
		}
	}
	return nil
}

func launchAgentTarget(u *user.User) (string, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return "", fmt.Errorf("desktop owner is unavailable")
	}
	return fmt.Sprintf("gui/%d/%s", uid, launchAgentLabel), nil
}

func launchctlAvailable(target string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/launchctl", "print", target)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func desktopAvailable(u *user.User) error {
	if err := terminalPrerequisites(); err != nil {
		return err
	}
	target, err := launchAgentTarget(u)
	if err != nil {
		return err
	}
	if !launchctlAvailable(target) {
		return fmt.Errorf("Aqua LaunchAgent is unavailable")
	}
	return nil
}

func platformDoctor(u *user.User) map[string]any {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	guiAvailable := err == nil && launchctlAvailable(fmt.Sprintf("gui/%d", uid))
	target, targetErr := launchAgentTarget(u)
	registered := targetErr == nil && launchctlAvailable(target)
	terminal, terminalErr := os.Stat(terminalApp)
	return map[string]any{
		"gui_domain_available":      guiAvailable,
		"launch_agent_registered":   registered,
		"terminal_available":        terminalErr == nil && terminal.IsDir(),
		"terminal_launcher_trusted": trustedLauncher(terminalLauncher, 0) == nil,
	}
}

func platformDoctorOK(checks map[string]any) bool {
	for _, name := range []string{"gui_domain_available", "launch_agent_registered", "terminal_available", "terminal_launcher_trusted"} {
		available, _ := checks[name].(bool)
		if !available {
			return false
		}
	}
	return true
}

func startSession(startCtx context.Context, u *user.User, _ Policy) error {
	if err := terminalPrerequisites(); err != nil {
		return err
	}
	target, err := launchAgentTarget(u)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(startCtx, "/bin/launchctl", "kickstart", target)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func terminalPrerequisites() error {
	if err := trustedLauncher(terminalLauncher, 0); err != nil {
		return err
	}
	s, err := os.Stat(terminalApp)
	if err != nil || !s.IsDir() {
		return fmt.Errorf("Terminal.app is unavailable")
	}
	return nil
}

func connectSession(ctx context.Context, u *user.User, p Policy, socket string) (net.Conn, error) {
	return connectStartedSession(ctx, socket, func(ctx context.Context) error {
		return startSession(ctx, u, p)
	})
}
