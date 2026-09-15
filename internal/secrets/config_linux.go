package secrets

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Version is set by the release build. It does not affect protocol negotiation.
var Version = "dev"

func loadConfig() (Config, error) {
	fd, err := unix.Open(ConfigPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return Config{}, fmt.Errorf("op-bridge is not configured; see the installation guide")
	}
	f := os.NewFile(uintptr(fd), ConfigPath)
	defer f.Close()
	if err := trustedConfigFile(f); err != nil {
		return Config{}, err
	}
	return decodeConfig(f)
}

func trustedConfigFile(f *os.File) error {
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm()&022 != 0 {
		return fmt.Errorf("unsafe system configuration")
	}
	if st, ok := s.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return fmt.Errorf("configuration must be owned by root")
	}
	return nil
}

func historyPath(u *user.User) string {
	return filepath.Join(u.HomeDir, ".local", "state", "op-bridge", "history")
}

// These commands inspect explicitly named staging files. They never select a
// runtime policy or install anything, and require no live configuration.
func configCommand(args []string, output, errorOutput io.Writer) (bool, int) {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(output, "op-bridge "+Version)
		return true, 0
	}
	if len(args) == 0 || args[0] != "config" {
		return false, 0
	}
	if len(args) != 3 || (args[1] != "check" && args[1] != "sudoers") {
		fmt.Fprintln(errorOutput, "usage: op-bridge config check|sudoers FILE")
		return true, 1
	}
	f, err := os.Open(args[2])
	if err != nil {
		fmt.Fprintln(errorOutput, "cannot open configuration file")
		return true, 1
	}
	defer f.Close()
	c, err := decodeConfig(f)
	if err != nil {
		fmt.Fprintln(errorOutput, err)
		return true, 1
	}
	if args[1] == "check" {
		fmt.Fprintln(output, "configuration valid (file ownership and live prerequisites not checked)")
		return true, 0
	}
	if c.Local == nil {
		fmt.Fprintln(errorOutput, "client-only configurations need no sudo rule")
		return true, 1
	}
	if c.Local.Caller == "" {
		fmt.Fprintln(errorOutput, "owner-only configurations need no sudo rule")
		return true, 1
	}
	_, err = fmt.Fprintf(output, "# Exactly this root-owned bridge, as the desktop owner, never root.\n# Validated list, read, create and edit requests arrive over stdin.\n%s ALL=(%s) NOPASSWD: NOSETENV: %s _bridge\n", c.Local.Caller, c.Local.Owner, InstalledBinary)
	if err != nil {
		return true, 1
	}
	return true, 0
}
