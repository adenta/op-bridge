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
	"time"
)

const opBinary = "/usr/bin/op"
const unitName = "op-bridge-session.service"

func desktopEnv(u *user.User, p Policy) []string {
	r := "/run/user/" + u.Uid
	return []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "XDG_CONFIG_HOME=" + filepath.Join(u.HomeDir, ".config"), "XDG_RUNTIME_DIR=" + r, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + r + "/bus", "OP_ACCOUNT=" + p.Account, "OP_BIOMETRIC_UNLOCK_ENABLED=true", "OP_CACHE=false"}
}

func runtimePaths(u *user.User) (string, string) {
	d := "/run/user/" + u.Uid + "/op-bridge"
	return d, d + "/session.sock"
}

func validateRuntimeParent(*user.User) error { return nil }

func platformDoctor(u *user.User) map[string]any {
	return map[string]any{"desktop_bus_available": desktopAvailable(u) == nil}
}

func platformDoctorOK(checks map[string]any) bool {
	available, _ := checks["desktop_bus_available"].(bool)
	return available
}

func desktopAvailable(u *user.User) error {
	_, err := os.Stat("/run/user/" + u.Uid + "/bus")
	return err
}
func startSession(startCtx context.Context, u *user.User, p Policy) error {
	cmd := exec.CommandContext(startCtx, "/usr/bin/systemd-run", "--user", "--quiet", "--collect", "--unit="+unitName, "--property=Restart=no", "--property=UMask=0077", "--property=KillMode=control-group", "--property=TimeoutStopSec=3s", InstalledBinary, "_serve")
	cmd.Env = desktopEnv(u, p)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()

}

// Preserve Linux's existing transient-service startup and polling behavior.
func connectSession(ctx context.Context, u *user.User, p Policy, socket string) (net.Conn, error) {
	startCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_ = startSession(startCtx, u, p)
	cancel()
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("request cancelled")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("desktop session could not start; run op-bridge session doctor")
}
