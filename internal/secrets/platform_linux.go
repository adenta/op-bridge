package secrets

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
)

const opBinary = "/usr/bin/op"

func desktopEnv(u *user.User, p Policy) []string {
	r := "/run/user/" + u.Uid
	return []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "XDG_CONFIG_HOME=" + filepath.Join(u.HomeDir, ".config"), "XDG_RUNTIME_DIR=" + r, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + r + "/bus", "OP_ACCOUNT=" + p.Account, "OP_BIOMETRIC_UNLOCK_ENABLED=true", "OP_CACHE=false"}
}

func runtimePaths(u *user.User) (string, string) {
	d := "/run/user/" + u.Uid + "/op-bridge"
	return d, d + "/session.sock"
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
func openPTY() (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	master := os.NewFile(uintptr(fd), "pty")
	cleanup := true
	defer func() {
		if cleanup {
			master.Close()
		}
	}()
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return nil, nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}

	cleanup = false
	return master, slave, nil
}
