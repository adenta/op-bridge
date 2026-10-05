package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const phoneUnit = "op-bridge-phone.service"
const phoneValueLimit = 64 * 1024
const phoneWireLimit = 512 * 1024

type phoneRequest struct {
	phoneSelection
	ID       string `json:"id"`
	Host     string `json:"host"`
	Caller   string `json:"caller"`
	Deadline int64  `json:"deadline"`
	State    string `json:"state"`
}
type phoneEntry struct {
	request phoneRequest
	result  chan []byte
	ctx     context.Context
}
type phoneSession struct {
	mu                sync.Mutex
	entries           map[string]*phoneEntry
	order             []string
	pending           int
	started, timeLast time.Time
	idle, maxAge      time.Duration
	host, caller      string
	policy            Policy
	history           func(historyEvent) error
}

func newPhoneSession(host, caller, account string) *phoneSession {
	now := time.Now()
	return &phoneSession{entries: map[string]*phoneEntry{}, started: now, timeLast: now, idle: sessionIdleLimit, maxAge: workerLifetime, host: host, caller: caller, policy: Policy{Account: account}}
}
func phoneFailure(code string) Response   { r := notStarted(code); r.ErrorCode = code; return r }
func phoneUncertain(code string) Response { r := phoneFailure(code); r.NotStarted = false; return r }
func (s *phoneSession) add(ctx context.Context, selection phoneSelection) (*phoneEntry, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.started) >= s.maxAge {
		return nil, "session_expired"
	}
	if s.pending >= 16 {
		return nil, "queue_full"
	}
	if len(s.entries) >= 128 {
		for i, id := range s.order {
			e := s.entries[id]
			if e.request.State != "pending" && e.request.State != "releasing" {
				delete(s.entries, id)
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
	}
	deadline, _ := ctx.Deadline()
	e := &phoneEntry{request: phoneRequest{phoneSelection: selection, ID: uuid.NewString(), Host: s.host, Caller: s.caller, Deadline: deadline.UnixMilli(), State: "pending"}, result: make(chan []byte, 1), ctx: ctx}
	s.entries[e.request.ID] = e
	s.order = append(s.order, e.request.ID)
	s.pending++
	return e, ""
}
func (s *phoneSession) finish(e *phoneEntry, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.request.State = state
	s.pending--
	s.timeLast = time.Now()
	select {
	case value := <-e.result:
		clear(value)
	default:
	}
}
func (s *phoneSession) expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending == 0 && (time.Since(s.timeLast) >= s.idle || time.Since(s.started) >= s.maxAge)
}
func (s *phoneSession) snapshot(id string) []phoneRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []phoneRequest{}
	for key, e := range s.entries {
		if id == key || id == "" && e.request.State == "pending" && e.ctx.Err() == nil {
			out = append(out, e.request)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Deadline < out[j].Deadline })
	return out
}
func (s *phoneSession) decide(id, method, value string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[id]
	if e == nil {
		return "unknown_request"
	}
	if e.request.State != "pending" || e.ctx.Err() != nil {
		return "request_not_pending"
	}
	if method == "release" {
		if len(value) == 0 || len(value) > phoneValueLimit || !utf8.ValidString(value) {
			return "invalid_value"
		}
		e.request.State = "releasing"
		e.result <- []byte(value)
	} else {
		e.request.State = "denied"
		e.result <- nil
	}
	return ""
}

func checkPhonePeer(conn net.Conn) bool {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return false
	}
	var credential *unix.Ucred
	err = raw.Control(func(fd uintptr) { credential, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	return err == nil && credential != nil && credential.Uid == uint32(os.Geteuid())
}
func (s *phoneSession) handleCaller(parent context.Context, conn net.Conn, stop context.CancelFunc) {
	defer conn.Close()
	if !checkPhonePeer(conn) {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(conn, MaxRequest+1024))
	decoder.DisallowUnknownFields()
	var r Request
	if decoder.Decode(&r) != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if _, err := s.policy.Validate(r); err != nil {
		json.NewEncoder(conn).Encode(phoneFailure("invalid_request"))
		return
	}
	if r.Action == "status" {
		data, _ := json.Marshal(map[string]any{"session": "running", "pending": len(s.snapshot("")), "approval": "manual_phone"})
		json.NewEncoder(conn).Encode(Response{Version: Protocol, Stdout: append(data, '\n')})
		return
	}
	if r.Action == "stop" {
		json.NewEncoder(conn).Encode(Response{Version: Protocol, Stdout: []byte("session: stopping\n")})
		stop()
		return
	}
	selection, err := phoneRead(s.policy, r)
	if err != nil {
		json.NewEncoder(conn).Encode(phoneFailure("unsupported_operation"))
		return
	}
	if r.Timeout == 0 {
		r.Timeout = 300
	}
	ctx, cancel := context.WithTimeout(parent, timeoutFor(r))
	defer cancel()
	closeOnCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer closeOnCancel()
	entry, code := s.add(ctx, selection)
	if code != "" {
		json.NewEncoder(conn).Encode(phoneFailure(code))
		return
	}
	state := "cancelled"
	event := s.policy.requestHistory(r, entry.request.ID)
	record := func() {
		if s.history != nil {
			if s.history(event) != nil {
				fmt.Fprint(os.Stderr, historyWarning)
			}
		}
	}
	record()
	defer func() {
		s.finish(entry, state)
		event.Event = "outcome"
		event.Outcome = "failure"
		event.Reason = "phone_" + state
		if state == "completed" {
			event.Outcome = "success"
		}
		if state == "delivery_uncertain" {
			event.Outcome = "unknown"
		}
		record()
	}()
	ack := make(chan string, 1)
	go func() {
		var message struct {
			Ack string `json:"ack"`
		}
		if decoder.Decode(&message) != nil {
			cancel()
			return
		}
		ack <- message.Ack
	}()
	var value []byte
	select {
	case value = <-entry.result:
	case <-ctx.Done():
		if parent.Err() == nil && ctx.Err() == context.DeadlineExceeded {
			state = "expired"
		}
		return
	}
	if value == nil {
		state = "denied"
		json.NewEncoder(conn).Encode(phoneFailure("denied"))
		return
	}
	defer clear(value)
	if ctx.Err() != nil {
		return
	}
	state = "delivery_uncertain"
	if selection.Newline {
		value = append(value, '\n')
	}
	defer clear(value)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	response := Response{Version: Protocol, Stdout: value, RequestID: entry.request.ID}
	if json.NewEncoder(conn).Encode(response) != nil {
		return
	}
	select {
	case id := <-ack:
		if id == entry.request.ID {
			state = "completed"
		}
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

type approvalMessage struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Method    string `json:"method"`
	RequestID string `json:"request_id,omitempty"`
	Value     string `json:"value,omitempty"`
}
type approvalReply struct {
	Version  int            `json:"version"`
	ID       string         `json:"id"`
	Requests []phoneRequest `json:"requests,omitempty"`
	Error    string         `json:"error,omitempty"`
}

func (s *phoneSession) approval(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || r.Header.Get("Origin") != "" {
		http.Error(w, "Not found", 404)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(phoneWireLimit)
	for {
		typ, data, err := c.Read(r.Context())
		if err != nil {
			return
		}
		var msg approvalMessage
		valid := typ == websocket.MessageText && len(data) <= phoneWireLimit && json.Unmarshal(data, &msg) == nil && msg.Version == 1 && len(msg.ID) > 0 && len(msg.ID) <= 80
		clear(data)
		if !valid {
			return
		}
		reply := approvalReply{Version: 1, ID: msg.ID}
		switch msg.Method {
		case "list":
			reply.Requests = s.snapshot("")
		case "get":
			if msg.RequestID == "" {
				reply.Error = "invalid_request"
			} else {
				reply.Requests = s.snapshot(msg.RequestID)
				if len(reply.Requests) == 0 {
					reply.Error = "unknown_request"
				}
			}
		case "release", "deny":
			reply.Error = s.decide(msg.RequestID, msg.Method, msg.Value)
			reply.Requests = s.snapshot(msg.RequestID)
		default:
			reply.Error = "unsupported_operation"
		}
		msg.Value = ""
		encoded, _ := json.Marshal(reply)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		err = c.Write(ctx, websocket.MessageText, encoded)
		cancel()
		if err != nil {
			return
		}
	}
}

func phoneDirectory() string { return fmt.Sprintf("/run/user/%d/op-bridge-phone", os.Geteuid()) }
func phoneOwner(c Config) (Desktop, error) {
	for _, d := range c.Desktops {
		if d.Transport == "remote-codex" {
			u, e := user.Lookup(d.Owner)
			if e != nil || u.Uid != strconv.Itoa(os.Geteuid()) || u.Uid == "0" {
				return d, fmt.Errorf("phone destination owner required")
			}
			return d, nil
		}
	}
	return Desktop{}, fmt.Errorf("phone destination is not configured")
}
func privatePhoneDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	s, e := os.Lstat(path)
	if e != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return fmt.Errorf("unsafe phone runtime")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unsafe phone runtime owner")
	}
	return nil
}
func phoneListen(path string) (net.Listener, error) {
	if st, err := os.Lstat(path); err == nil {
		meta, ok := st.Sys().(*syscall.Stat_t)
		if !ok || meta.Uid != uint32(os.Geteuid()) || st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("unsafe phone socket")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

type peerListener struct {
	net.Listener
	slots chan struct{}
}
type slottedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *slottedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if !checkPhonePeer(c) {
			c.Close()
			continue
		}
		select {
		case l.slots <- struct{}{}:
			return &slottedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
func runPhone(c Config) error {
	d, err := phoneOwner(c)
	if err != nil {
		return err
	}
	dir := phoneDirectory()
	if err = privatePhoneDirectory(dir); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(dir, "owner.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("phone session already active")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	callers, err := phoneListen(filepath.Join(dir, "caller.sock"))
	if err != nil {
		return err
	}
	defer callers.Close()
	approvals, err := phoneListen(filepath.Join(dir, "approval.sock"))
	if err != nil {
		return err
	}
	defer approvals.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	s := newPhoneSession(c.Machine, d.Owner, d.Account)
	u, err := user.Current()
	if err != nil {
		return err
	}
	history := &accessHistory{dir: historyPath(u), now: time.Now}
	s.history = history.append
	httpServer := &http.Server{Handler: http.HandlerFunc(s.approval), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 * 1024, BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: nil}
	defer httpServer.Close()
	go func() { _ = httpServer.Serve(peerListener{approvals, make(chan struct{}, 8)}); stop() }()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				callers.Close()
				return
			case <-ticker.C:
				if s.expired() {
					stop()
				}
			}
		}
	}()
	var handlers sync.WaitGroup
	defer func() { stop(); handlers.Wait() }()
	slots := make(chan struct{}, 32)
	for {
		conn, err := callers.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		handlers.Add(1)
		go func() { defer handlers.Done(); defer func() { <-slots }(); s.handleCaller(ctx, conn, stop) }()
	}
}
func dialPhone(path string) (net.Conn, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	meta, ok := st.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != uint32(os.Geteuid()) || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("unsafe phone socket")
	}
	c, e := net.DialTimeout("unix", path, time.Second)
	if e != nil {
		return nil, e
	}
	if !checkPhonePeer(c) {
		c.Close()
		return nil, fmt.Errorf("phone peer mismatch")
	}
	return c, nil
}
func phoneDispatch(ctx context.Context, c Config, d Desktop, r Request) Response {
	owner, err := phoneOwner(c)
	if err != nil || owner.Owner != d.Owner {
		return phoneFailure("phone_owner_required")
	}
	if r.Action == "read" {
		if _, err = phoneRead(Policy{Account: d.Account}, r); err != nil {
			return phoneFailure("unsupported_operation")
		}
	} else if r.Action != "status" && r.Action != "stop" && r.Action != "doctor" {
		return phoneFailure("unsupported_operation")
	}
	if r.Timeout == 0 {
		r.Timeout = 300
	}
	dir := phoneDirectory()
	if r.Action == "doctor" {
		data, _ := json.Marshal(map[string]any{"approval": "manual_phone", "owner": d.Owner, "runtime": dir, "account": d.Account})
		return Response{Version: Protocol, Stdout: append(data, '\n')}
	}
	if _, statErr := os.Lstat(dir); os.IsNotExist(statErr) && r.Action != "read" {
		return Response{Version: Protocol, Stdout: []byte("session: stopped\n")}
	}
	if err = privatePhoneDirectory(dir); err != nil {
		return phoneFailure("unsafe_phone_runtime")
	}
	path := filepath.Join(dir, "caller.sock")
	conn, err := dialPhone(path)
	if err != nil && r.Action != "read" {
		return Response{Version: Protocol, Stdout: []byte("session: stopped\n")}
	}
	if err != nil {
		// The shared startup lock prevents concurrent callers from launching duplicates.
		conn, err = connectStartedSession(ctx, path, func(startCtx context.Context) error {
			cmd := exec.CommandContext(startCtx, "/usr/bin/systemd-run", "--user", "--quiet", "--collect", "--unit="+phoneUnit, "--property=Restart=no", "--property=UMask=0077", "--property=KillMode=control-group", "--property=TimeoutStopSec=3s", InstalledBinary, "_phone")
			cmd.Env = append(os.Environ(), fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Geteuid()), fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Geteuid()))
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			return cmd.Run()
		})
		if err != nil {
			return phoneFailure("phone_session_unavailable")
		}
	}
	defer conn.Close()
	if !checkPhonePeer(conn) {
		return phoneFailure("phone_peer_mismatch")
	}
	end := context.AfterFunc(ctx, func() { conn.Close() })
	defer end()
	_ = conn.SetDeadline(time.Now().Add(timeoutFor(r) + 5*time.Second))
	return exchangePhone(conn, r)
}
func exchangePhone(conn net.Conn, r Request) Response {
	if json.NewEncoder(conn).Encode(r) != nil {
		return phoneUncertain("phone_submission_uncertain")
	}
	var result Response
	if json.NewDecoder(io.LimitReader(conn, 2*phoneValueLimit+4096)).Decode(&result) != nil {
		return phoneUncertain("phone_session_ended_or_timed_out")
	}
	if result.Version != Protocol {
		return phoneUncertain("protocol_mismatch")
	}
	if result.Exit == 0 && result.RequestID != "" {
		if json.NewEncoder(conn).Encode(map[string]string{"ack": result.RequestID}) != nil {
			clear(result.Stdout)
			return phoneUncertain("delivery_uncertain")
		}
	}
	return result
}
