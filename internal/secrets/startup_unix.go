//go:build linux || (darwin && arm64)

package secrets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const terminalStartupLimit = 15 * time.Second

// connectStartedSession serializes Mac startup across bridge processes, not just
// goroutines. Keep the lock until the socket is reachable; open/launchctl can
// return before Terminal has executed the command. The lock file must persist:
// unlinking it would let waiters lock different inodes.
func connectStartedSession(ctx context.Context, socket string, start func(context.Context) error) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, terminalStartupLimit)
	defer cancel()
	fd, err := unix.Open(filepath.Join(filepath.Dir(socket), "startup.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("terminal startup lock unavailable")
	}
	lock := os.NewFile(uintptr(fd), "startup.lock")
	defer lock.Close()
	s, err := lock.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("unsafe terminal startup lock")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return nil, fmt.Errorf("unsafe terminal startup lock owner or links")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("terminal startup cancelled or timed out: %w", err)
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return nil, fmt.Errorf("terminal startup lock failed")
		}
		if err := startupPause(ctx); err != nil {
			return nil, err
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	ready := func(conn net.Conn) (net.Conn, error) {
		if err := lock.Truncate(0); err != nil {
			conn.Close()
			return nil, fmt.Errorf("could not clear terminal startup marker")
		}
		return conn, nil
	}
	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	if conn, err := dialer.DialContext(ctx, "unix", socket); err == nil {
		return ready(conn)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("terminal startup cancelled or timed out: %w", err)
	}
	// A cancelled bridge process cannot keep holding flock while Terminal opens.
	// Leave a one-byte, timestamped marker until readiness, so the next caller
	// waits for that attempt instead of opening another window. No request data
	// is stored and failed attempts are never automatically resubmitted here.
	s, err = lock.Stat()
	if err != nil {
		return nil, fmt.Errorf("terminal startup marker unavailable")
	}
	recentAttempt := s.Size() != 0 && time.Since(s.ModTime()) < terminalStartupLimit
	if !recentAttempt {
		if _, err := lock.WriteAt([]byte{1}, 0); err != nil {
			return nil, fmt.Errorf("could not record terminal startup attempt")
		}
		if err := lock.Truncate(1); err != nil {
			return nil, fmt.Errorf("could not bound terminal startup marker")
		}
		if err := start(ctx); err != nil {
			return nil, fmt.Errorf("hidden Terminal launcher failed; run op-bridge session doctor: %w", err)
		}
	}
	for {
		if conn, err := dialer.DialContext(ctx, "unix", socket); err == nil {
			return ready(conn)
		}
		if err := startupPause(ctx); err != nil {
			return nil, err
		}
	}
}

func startupPause(ctx context.Context) error {
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("hidden Terminal did not become ready: startup cancelled or timed out; run op-bridge session doctor: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// Validate the fixed launcher and all its parent directories. A root-owned
// script in a caller-writable directory would still be replaceable.
func trustedLauncher(path string, ownerUID uint32) error {
	return inspectLauncher(path, ownerUID, os.Lstat)
}

func inspectLauncher(path string, ownerUID uint32, lstat func(string) (os.FileInfo, error)) error {
	for current := path; ; current = filepath.Dir(current) {
		s, err := lstat(current)
		if err != nil {
			return fmt.Errorf("Terminal launcher is missing or inaccessible")
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != ownerUID || s.Mode().Perm()&0022 != 0 || s.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Terminal launcher or parent is not trusted")
		}
		if current == path {
			if !s.Mode().IsRegular() || s.Mode().Perm()&0111 != 0111 {
				return fmt.Errorf("Terminal launcher must be an executable regular file")
			}
		} else if !s.IsDir() {
			return fmt.Errorf("Terminal launcher parent is not a directory")
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}
