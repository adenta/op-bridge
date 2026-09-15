//go:build linux

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const ConfigPath = "/etc/op-bridge.json"
const InstalledBinary = "/usr/local/libexec/op-bridge/op-bridge"
const unitName = "op-bridge-session.service"
const sessionIdleLimit = 2 * time.Minute
const workerLifetime = 10 * time.Minute

func owner(c Config) (*user.User, error) {
	if c.Local == nil {
		return nil, fmt.Errorf("local desktop bridge is not configured")
	}
	u, err := user.Lookup(c.Local.Owner)
	if err != nil || u.Uid == "0" {
		return nil, fmt.Errorf("desktop owner is unavailable")
	}
	return u, nil
}

func privateRuntime(u *user.User) (string, error) {
	d, socket := runtimePaths(u)
	if err := os.Mkdir(d, 0700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("desktop runtime is unavailable; log in to the configured desktop as %s", u.Username)
	}
	s, err := os.Lstat(d)
	if err != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return "", fmt.Errorf("unsafe runtime directory")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || strconv.FormatUint(uint64(st.Uid), 10) != u.Uid {
		return "", fmt.Errorf("runtime owner mismatch")
	}
	return socket, nil
}

func decodeRequest(r io.Reader, p Policy) (Request, error) {
	var req Request
	d := json.NewDecoder(io.LimitReader(r, MaxRequest))
	d.DisallowUnknownFields()
	err := d.Decode(&req)
	if err != nil {
		return req, fmt.Errorf("invalid request")
	}
	_, err = p.Validate(req)
	return req, err
}

// JSON decoding can finish before trailing whitespace reaches the reader.
// Drain the remaining transport until EOF or a read error: receiving another
// byte is not a disconnect. No further requests are accepted on this transport.
func cancelOnDisconnect(input io.Reader, cancel context.CancelFunc) {
	_, _ = io.Copy(io.Discard, input)
	cancel()
}

// Read user stdin to completion before opening the separate, long-lived
// transport pipe. EOF in a template must not cancel the submitted request.
func readWriteInput(r *Request, input io.Reader, p Policy) error {
	data, err := io.ReadAll(io.LimitReader(input, MaxRequest+1))
	if err != nil {
		return fmt.Errorf("could not read JSON input")
	}
	r.Stdin = data
	_, err = p.Validate(*r)
	return err
}

func uncertainWrite(r Request, result Response) Response {
	if r.Action == "write" && !result.NotStarted && result.Error != "" && !strings.Contains(result.Error, "protocol mismatch") && !strings.Contains(result.Error, "write result is unknown") {
		result.Error += "; write result is unknown: check the item before retrying"
	}
	return result
}

func timeoutFor(r Request) time.Duration {
	if r.Timeout == 0 {
		return 120 * time.Second
	}
	return time.Duration(r.Timeout) * time.Second
}

func Main(args []string, input io.Reader, output, errorOutput io.Writer) int {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h")) {
		fmt.Fprintln(output, "Usage: op-bridge [--desktop NAME] [--timeout SECONDS] vault list|item list|item get ITEM|read REFERENCE [op options]\n       op-bridge [--desktop NAME] [--timeout SECONDS] item create - [--vault VAULT] [--format FORMAT] [--dry-run] < item.json\n       op-bridge [--desktop NAME] [--timeout SECONDS] item edit ITEM [--vault VAULT] [--format FORMAT] [--dry-run] < item.json\n       op-bridge [--desktop NAME] session status|doctor|stop\n       op-bridge [--desktop NAME] route show [--format=json]\nWrites require JSON on stdin; no file options or attachments. Linux with a configured 1Password approval desktop. Overrides apply to this invocation. Session stop affects all tasks on the selected desktop. Output can contain secrets.")
		fmt.Fprintln(output, "Sessions expire after 2 idle minutes; terminal approval reuse is capped at 10 minutes, allowing active operations to finish. Every secret operation requires a desktop notification (5-second expiry, vault/item identifiers only). Unavailable notifications block access. Status reports session limits; doctor checks notification-service availability. Desktop settings may suppress banners.")
		fmt.Fprintln(output, "Setup: op-bridge config check|sudoers FILE (inspect staging policy only). Version: op-bridge --version.")
		return 0
	}
	if handled, code := configCommand(args, output, errorOutput); handled {
		return code
	}
	c, err := loadConfig()
	if err != nil {
		fmt.Fprintln(errorOutput, err)
		return 1
	}
	if len(args) == 1 && strings.HasPrefix(args[0], "_") {
		u, e := owner(c)
		if e != nil || c.Local == nil || strconv.Itoa(os.Geteuid()) != u.Uid {
			fmt.Fprintln(errorOutput, "desktop owner required")
			return 1
		}
		switch args[0] {
		case "_bridge":
			r, e := decodeRequest(input, Policy{Account: c.Local.Account})
			var result Response
			if e != nil {
				result = notStarted(e.Error())
			} else {
				ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
				defer cancel()
				// The client keeps stdin open until the response. SSH disconnect
				// closes it even when sshd sends no signal to a non-PTY command.
				go cancelOnDisconnect(input, cancel)
				result = bridge(ctx, c, u, r)
			}
			if json.NewEncoder(output).Encode(result) != nil {
				return 1
			}
			return 0
		case "_serve":
			if err := serve(c, u, sessionIdleLimit); err != nil {
				fmt.Fprintln(errorOutput, err)
				return 1
			}
			return 0
		case "_worker":
			return runWorker(input, output, opBinary, desktopEnv(u, Policy{Account: c.Local.Account}), Policy{Account: c.Local.Account})
		}
		fmt.Fprintln(errorOutput, "unsupported internal command")
		return 1
	}
	return runClient(c, args, input, output, errorOutput, dispatch)
}

func external(ctx context.Context, r Request, program string, args []string, message string) (result Response) {
	submitted := false
	defer func() {
		if submitted {
			result = uncertainWrite(r, result)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, timeoutFor(r)+15*time.Second)
	defer cancel()
	data, _ := json.Marshal(r)
	cmd := exec.CommandContext(ctx, program, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return failure(message)
	}
	defer stdin.Close()
	cmd.Stderr = io.Discard
	var b limitedBuffer
	b.limit = MaxResponse
	cmd.Stdout = &b
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return failure(message)
	}
	submitted = true
	if _, err := stdin.Write(append(data, '\n')); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return failure(message)
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return failure("request cancelled or timed out")
		}
		return failure(message)
	}
	if json.Unmarshal(b.data, &result) != nil {
		return failure("invalid bridge response; update both hosts")
	}
	return result
}

func bridge(ctx context.Context, c Config, u *user.User, r Request) Response {
	if _, err := (Policy{Account: c.Local.Account}).Validate(r); err != nil {
		return notStarted(err.Error())
	}
	_, socket := runtimePaths(u)
	if r.Action == "doctor" {
		_, opErr := os.Stat(opBinary)
		runtimeErr := desktopAvailable(u)
		notifications := desktopNotifications{socket: "/run/user/" + u.Uid + "/bus", policy: Policy{Account: c.Local.Account}}
		notificationsAvailable := notifications.available(ctx)
		data, _ := json.Marshal(map[string]any{"desktop_user": u.Username, "account": c.Local.Account, "cli_available": opErr == nil, "desktop_bus_available": runtimeErr == nil, "notification_service_available": notificationsAvailable})
		result := Response{Version: Protocol, Stdout: append(data, '\n')}
		if opErr != nil || runtimeErr != nil || !notificationsAvailable {
			result.Exit = 1
		}
		return result
	}
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil && r.Action != "read" && r.Action != "write" {
		return Response{Version: Protocol, Stdout: []byte("session: stopped\n")}
	}
	if err != nil {
		if _, e := privateRuntime(u); e != nil {
			return failure(e.Error())
		}
		startCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = startSession(startCtx, u, Policy{Account: c.Local.Account})
		cancel()
		for i := 0; i < 50; i++ {
			conn, err = net.DialTimeout("unix", socket, 100*time.Millisecond)
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return failure("request cancelled")
			case <-time.After(100 * time.Millisecond):
			}
		}
		if err != nil {
			return failure("desktop session could not start; run op-bridge session doctor")
		}
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(timeoutFor(r) + 5*time.Second))
	if json.NewEncoder(conn).Encode(r) != nil {
		return uncertainWrite(r, failure("session connection failed"))
	}
	var result Response
	if json.NewDecoder(io.LimitReader(conn, MaxResponse)).Decode(&result) != nil {
		return uncertainWrite(r, failure("session ended or request timed out"))
	}
	return uncertainWrite(r, result)
}

// limitedBuffer prevents a CLI or transport response from exhausting memory.
type limitedBuffer struct {
	data  []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, fmt.Errorf("output limit exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

type worker struct {
	cmd     *exec.Cmd
	in      io.WriteCloser
	out     io.ReadCloser
	tty     *os.File
	decoder *json.Decoder
	nextID  uint64
	started time.Time
}

// This envelope exists only on the private parent/worker pipe. Cancellation is
// ordered on that pipe and names one operation, so it cannot cancel a later one.
type workerMessage struct {
	ID      uint64  `json:"id"`
	Cancel  bool    `json:"cancel,omitempty"`
	Request Request `json:"request"`
}

func (w *worker) send(r Request) (uint64, error) {
	w.nextID++
	return w.nextID, json.NewEncoder(w.in).Encode(workerMessage{ID: w.nextID, Request: r})
}

func startWorker(program string, args, env []string) (*worker, error) {
	started := time.Now()
	master, slave, err := openPTY()
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			master.Close()
		}
	}()
	defer slave.Close()
	cmd := exec.Command(program, args...)
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{slave}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	cleanup = false
	// No command data uses this PTY. Drain unexpected terminal writes without storage.
	go io.Copy(io.Discard, master)
	return &worker{cmd: cmd, in: in, out: out, tty: master, decoder: json.NewDecoder(out), started: started}, nil
}

func (w *worker) close() {
	w.in.Close()
	_ = w.cmd.Process.Kill()
	w.out.Close()
	w.tty.Close()
	_ = w.cmd.Wait()
}

func runWorker(input io.Reader, output io.Writer, op string, env []string, p Policy) int {
	var mu sync.Mutex
	var cancel context.CancelFunc
	var activeID uint64
	var work sync.WaitGroup
	defer func() {
		mu.Lock()
		if cancel != nil {
			cancel()
		}
		mu.Unlock()
		work.Wait()
	}()
	d := json.NewDecoder(io.LimitReader(input, 1<<40))
	for {
		var message workerMessage
		if err := d.Decode(&message); err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			return 1
		}
		mu.Lock()
		if message.Cancel {
			if cancel != nil && activeID == message.ID {
				cancel()
			}
			mu.Unlock()
			continue
		}
		if cancel != nil {
			mu.Unlock()
			return 1
		}
		r := message.Request
		args, err := p.Validate(r)
		if err != nil || (r.Action != "read" && r.Action != "write") {
			mu.Unlock()
			return 1
		}
		ctx, stop := context.WithTimeout(context.Background(), timeoutFor(r))
		cancel, activeID = stop, message.ID
		work.Add(1)
		mu.Unlock()
		go func() {
			defer work.Done()
			response := uncertainWrite(r, execute(ctx, op, args, env, r.Stdin))
			stop()
			mu.Lock()
			defer mu.Unlock()
			cancel = nil
			_ = json.NewEncoder(output).Encode(response)
		}()
	}
}

func execute(ctx context.Context, op string, args, env []string, input []byte) Response {
	cmd := exec.CommandContext(ctx, op, args...)
	cmd.Env = env
	cmd.Stdin = nil
	if input != nil {
		// os/exec connects a non-file Reader through an OS pipe. Native op
		// detects this as piped JSON, unlike Node's socket-backed stdin.
		cmd.Stdin = bytes.NewReader(input)
	}
	// Do not use Setsid here: every op child must keep the worker's controlling TTY.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr limitedBuffer
	stdout.limit = MaxOutput
	stderr.limit = MaxOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		if errors.Is(err, context.Canceled) {
			return failure("1Password request cancelled before CLI startup")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return failure("1Password request timed out before CLI startup")
		}
		// Start errors describe the fixed executable/stdio path and OS failure;
		// never include cmd.String(), request arguments, input, or environment.
		return failure(fmt.Sprintf("1Password CLI could not start: %v", err))
	}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-finished:
			return
		case <-ctx.Done():
		}
		select {
		case <-finished:
			return
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}()
	err := cmd.Wait()
	if ctx.Err() != nil {
		return failure("1Password request cancelled or authorization timed out")
	}
	r := Response{Version: Protocol, Stdout: stdout.data, Stderr: stderr.data}
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			r.Exit = e.ExitCode()
			if r.Exit < 0 {
				r.Exit = 1
			}
		} else {
			return failure("1Password output limit or execution failure")
		}
	}
	return r
}

func serve(c Config, u *user.User, idle time.Duration) error {
	socket, err := privateRuntime(u)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(filepath.Dir(socket), "owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fmt.Errorf("session already running")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if s, e := os.Lstat(socket); e == nil {
		if s.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("unsafe socket path")
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer cancel()
	notifications := desktopNotifications{socket: "/run/user/" + u.Uid + "/bus", policy: Policy{Account: c.Local.Account}}
	history := &accessHistory{dir: historyPath(u), now: time.Now}
	record := history.append
	if err := record(historyEvent{}); err != nil {
		fmt.Fprint(os.Stderr, historyWarning)
	}
	return serveRequests(ctx, cancel, listener, sessionPolicy{
		policy: Policy{Account: c.Local.Account},
		idle:   idle, maxAge: workerLifetime,
		start: func() (*worker, error) {
			return startWorker(InstalledBinary, []string{"_worker"}, desktopEnv(u, Policy{Account: c.Local.Account}))
		},
		notify:  notifications.notify,
		history: record,
	})
}

type sessionPolicy struct {
	policy       Policy
	idle, maxAge time.Duration
	start        func() (*worker, error)
	notify       func(context.Context, Request) error
	history      func(historyEvent) error
}

func serveRequests(ctx context.Context, stop context.CancelFunc, listener net.Listener, policy sessionPolicy) error {
	w, err := policy.start()
	if err != nil {
		stop()
		listener.Close()
		return fmt.Errorf("terminal worker could not start")
	}
	var state sync.Mutex
	pending := 0
	last := time.Now()
	workerStarted := w.started
	serial := make(chan struct{}, 1)
	connections := make(chan struct{}, 32)
	var handlers sync.WaitGroup
	defer func() {
		stop()
		listener.Close()
		handlers.Wait()
		if w != nil {
			w.close()
		}
	}()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				listener.Close()
				return
			case <-ticker.C:
				state.Lock()
				expired := pending == 0 && (time.Since(last) >= policy.idle || time.Since(workerStarted) >= policy.maxAge)
				if expired {
					stop()
				}
				state.Unlock()
			}
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connections <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		handlers.Add(1)
		go func() {
			defer func() { <-connections }()
			defer handlers.Done()
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			r, err := decodeRequest(conn, policy.policy)
			_ = conn.SetReadDeadline(time.Time{})
			if err != nil {
				json.NewEncoder(conn).Encode(notStarted(err.Error()))
				return
			}
			if r.Action == "status" {
				state.Lock()
				age := time.Since(workerStarted)
				data, _ := json.Marshal(map[string]any{
					"session": "running", "pending": pending, "idle_seconds": int(time.Since(last).Seconds()), "account": policy.policy.Account,
					"idle_limit_seconds": int(policy.idle.Seconds()), "worker_age_seconds": int(age.Seconds()),
					"worker_lifetime_seconds": int(policy.maxAge.Seconds()), "reuse_remaining_seconds": max(0, (policy.maxAge - age).Seconds()),
				})
				state.Unlock()
				json.NewEncoder(conn).Encode(Response{Version: Protocol, Stdout: append(data, '\n')})
				return
			}
			if r.Action == "stop" {
				json.NewEncoder(conn).Encode(Response{Version: Protocol, Stdout: []byte("session: stopping\n")})
				stop()
				return
			}
			if r.Action != "read" && r.Action != "write" {
				json.NewEncoder(conn).Encode(failure("unsupported session request"))
				return
			}
			event := policy.policy.requestHistory(r, uuid.NewString())
			logFailed := false
			record := func() {
				if policy.history != nil {
					if err := policy.history(event); err != nil {
						logFailed = true
						fmt.Fprint(os.Stderr, historyWarning)
					}
				}
			}
			record()
			event.Event = "outcome"
			event.Outcome, event.Reason = "not_started", "session_stopping"
			reply := func(response Response) {
				record()
				if logFailed {
					response.Stderr = append(response.Stderr, []byte(historyWarning)...)
				}
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_ = json.NewEncoder(conn).Encode(response)
			}
			state.Lock()
			if ctx.Err() != nil {
				state.Unlock()
				reply(notStarted("session is stopping; operation not started"))
				return
			}
			if pending >= 16 {
				event.Reason = "queue_full"
				state.Unlock()
				reply(notStarted("session queue is full; operation not started"))
				return
			}
			pending++
			state.Unlock()
			defer func() { state.Lock(); pending--; last = time.Now(); state.Unlock() }()
			reqCtx, cancel := context.WithTimeout(ctx, timeoutFor(r))
			defer cancel()
			go cancelOnDisconnect(conn, cancel)
			select {
			case serial <- struct{}{}:
			case <-reqCtx.Done():
				event.Reason = "queued_cancelled"
				reply(notStarted("request cancelled or timed out while queued; operation not started"))
				return
			}
			defer func() { <-serial }()
			if reqCtx.Err() != nil {
				event.Reason = "cancelled_before_dispatch"
				reply(notStarted("request cancelled or timed out while queued; operation not started"))
				return
			}
			if err := policy.notify(reqCtx, r); err != nil {
				event.Reason = "notification_unavailable"
				reply(notStarted("desktop notification unavailable or not accepted; operation not started"))
				return
			}
			event.NotificationAccepted = true
			if reqCtx.Err() != nil {
				event.Reason = "cancelled_before_dispatch"
				reply(notStarted("request cancelled or timed out before dispatch; operation not started"))
				return
			}
			// Only the serial dispatcher owns w. Rotate after notification delivery
			// so crossing the age limit during that call cannot reuse approval.
			if time.Since(w.started) >= policy.maxAge {
				w.close()
				w, err = policy.start()
				if err != nil {
					stop()
					event.Reason = "worker_start_failed"
					reply(notStarted("terminal worker could not restart; operation not started"))
					return
				}
				state.Lock()
				workerStarted = w.started
				state.Unlock()
			}
			if reqCtx.Err() != nil {
				event.Reason = "cancelled_before_dispatch"
				reply(notStarted("request cancelled or timed out before dispatch; operation not started"))
				return
			}
			activeWorker := w
			event.Outcome, event.Reason = "unknown", "worker_transport_failed"
			id, err := w.send(r)
			if err != nil {
				stop()
				record()
				return
			}
			results := make(chan Response, 1)
			go func() {
				var response Response
				if activeWorker.decoder.Decode(&response) != nil {
					response = failure("terminal worker ended")
					stop()
				}
				results <- response
			}()
			var response Response
			select {
			case response = <-results:
			case <-reqCtx.Done():
				_ = json.NewEncoder(w.in).Encode(workerMessage{ID: id, Cancel: true})
				select {
				case response = <-results:
				case <-time.After(4 * time.Second):
					_ = w.cmd.Process.Kill()
					stop()
					response = failure("terminal worker did not stop")
				}
			}
			event.Reason = "execution_incomplete"
			if response.Error == "" {
				event.Exit = &response.Exit
				event.Outcome, event.Reason = "success", "native_exit"
				if response.Exit != 0 {
					event.Outcome = "failure"
				}
			} else if response.NotStarted {
				event.Outcome, event.Reason = "not_started", "worker_not_started"
			}
			reply(response)
		}()
	}
}
