//go:build linux || (darwin && arm64)

package secrets

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A fake launcher process, never Terminal or a real desktop/CLI.
func TestStartupProcess(t *testing.T) {
	if os.Getenv("OP_BRIDGE_FAKE_STARTUP") != "1" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("unix", os.Getenv("OP_BRIDGE_FAKE_SOCKET"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}

func fakeStartup(t *testing.T, socket string) func(context.Context) error {
	t.Helper()
	return func(context.Context) error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(exe, "-test.run=^TestStartupProcess$")
		cmd.Env = append(os.Environ(), "OP_BRIDGE_FAKE_STARTUP=1", "OP_BRIDGE_FAKE_SOCKET="+socket)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			return err
		}
		t.Cleanup(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		})
		return nil
	}
}

func TestStartupConcurrentCallersLaunchOnce(t *testing.T) {
	socket := shortSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var starts atomic.Int32
	fake := fakeStartup(t, socket)
	start := func(ctx context.Context) error {
		starts.Add(1)
		// Let other callers contend while the launcher has not produced a socket.
		time.Sleep(50 * time.Millisecond)
		return fake(ctx)
	}
	done := make(chan error, 12)
	for i := 0; i < cap(done); i++ {
		go func() {
			conn, err := connectStartedSession(ctx, socket, start)
			if err == nil {
				conn.Close()
			}
			done <- err
		}()
	}
	for i := 0; i < cap(done); i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if starts.Load() != 1 {
		t.Fatalf("launched %d times", starts.Load())
	}
}

func TestStartupExistingSocketDoesNotLaunch(t *testing.T) {
	socket := shortSocket(t)
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := connectStartedSession(ctx, socket, func(context.Context) error {
		t.Error("existing session was relaunched")
		return errors.New("unexpected launch")
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestStartupErrorsAndNoAutomaticRetry(t *testing.T) {
	for _, test := range []struct {
		name      string
		launchErr error
		want      string
	}{
		{"missing launcher", os.ErrNotExist, "launcher failed"},
		{"launcher failure", errors.New("fake launcher failed"), "launcher failed"},
		{"socket timeout", nil, "timed out"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			calls := 0
			conn, err := connectStartedSession(ctx, shortSocket(t), func(context.Context) error {
				calls++
				return test.launchErr
			})
			if conn != nil || err == nil || !strings.Contains(err.Error(), test.want) || calls != 1 {
				t.Fatalf("conn=%v err=%v launches=%d", conn, err, calls)
			}
		})
	}
}

func TestStartupCancellationWhileLocked(t *testing.T) {
	socket := shortSocket(t)
	f, err := os.OpenFile(filepath.Join(filepath.Dir(socket), "startup.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	_, err = connectStartedSession(ctx, socket, func(context.Context) error {
		t.Error("launched despite held lock")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestStartupStopAndRestart(t *testing.T) {
	socket := shortSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var listener net.Listener
	starts := 0
	start := func(context.Context) error {
		starts++
		var err error
		listener, err = net.Listen("unix", socket)
		return err
	}
	defer func() {
		if listener != nil {
			listener.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		conn, err := connectStartedSession(ctx, socket, start)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		listener.Close()
	}
	if starts != 2 {
		t.Fatalf("expected two generations, got %d", starts)
	}
}

func TestStartupRejectsUnsafeLock(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "writable"} {
		t.Run(kind, func(t *testing.T) {
			socket := shortSocket(t)
			lock := filepath.Join(filepath.Dir(socket), "startup.lock")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(filepath.Join(filepath.Dir(socket), "other"), lock)
			case "directory":
				err = os.Mkdir(lock, 0700)
			case "writable":
				err = os.WriteFile(lock, nil, 0600)
				if err == nil {
					err = os.Chmod(lock, 0666)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = connectStartedSession(context.Background(), socket, func(context.Context) error {
				t.Error("unsafe lock allowed launch")
				return nil
			})
			if err == nil {
				t.Fatal("unsafe lock accepted")
			}
		})
	}
}

type launcherInfo struct {
	mode os.FileMode
	uid  uint32
}

func (s launcherInfo) Name() string       { return "launcher" }
func (s launcherInfo) Size() int64        { return 0 }
func (s launcherInfo) Mode() os.FileMode  { return s.mode }
func (s launcherInfo) ModTime() time.Time { return time.Time{} }
func (s launcherInfo) IsDir() bool        { return s.mode.IsDir() }
func (s launcherInfo) Sys() any           { return &syscall.Stat_t{Uid: s.uid} }

func TestTrustedLauncherAndParents(t *testing.T) {
	const path = "/usr/local/libexec/op-bridge/Launch.command"
	for _, test := range []struct {
		name, change   string
		mode           os.FileMode
		uid            uint32
		missing, valid bool
	}{
		{name: "trusted", valid: true},
		{name: "missing", change: path, missing: true},
		{name: "not executable", change: path, mode: 0644},
		{name: "user owned", change: path, mode: 0755, uid: 501},
		{name: "writable file", change: path, mode: 0775},
		{name: "symlink", change: path, mode: os.ModeSymlink | 0755},
		{name: "writable parent", change: "/usr/local", mode: os.ModeDir | 0775},
		{name: "user owned parent", change: "/usr/local", mode: os.ModeDir | 0755, uid: 501},
		{name: "symlink parent", change: "/usr/local", mode: os.ModeSymlink | 0755},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := inspectLauncher(path, 0, func(p string) (os.FileInfo, error) {
				if p == test.change {
					if test.missing {
						return nil, os.ErrNotExist
					}
					return launcherInfo{mode: test.mode, uid: test.uid}, nil
				}
				mode := os.FileMode(0755)
				if p != path {
					mode |= os.ModeDir
				}
				return launcherInfo{mode: mode}, nil
			})
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}

func TestStartupCancellationDuringLaunchAndReadiness(t *testing.T) {
	for _, duringLaunch := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		_, err := connectStartedSession(ctx, shortSocket(t), func(ctx context.Context) error {
			cancel()
			if duringLaunch {
				return ctx.Err()
			}
			return nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	}
}

func TestStartupCancelledLauncherIsNotRepeated(t *testing.T) {
	socket := shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	fake := fakeStartup(t, socket)
	_, err := connectStartedSession(ctx, socket, func(ctx context.Context) error {
		err := fake(ctx)
		cancel()
		return err
	})
	cancel()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancelled launch: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := connectStartedSession(ctx, socket, func(context.Context) error {
		t.Error("opened another terminal after cancelled asynchronous launch")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestStartupExpiredMarkerAllowsFreshAttempt(t *testing.T) {
	socket := shortSocket(t)
	lock := filepath.Join(filepath.Dir(socket), "startup.lock")
	if err := os.WriteFile(lock, []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * terminalStartupLimit)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := connectStartedSession(ctx, socket, fakeStartup(t, socket))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
