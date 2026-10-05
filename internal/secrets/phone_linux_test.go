package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestPhoneReadContract(t *testing.T) {
	for _, args := range [][]string{{"read", "op://Vault/Item/password"}, {"read", "-n", "op://Vault/Item/section/field"}, {"item", "get", "item", "--fields", "password", "--vault", "vault", "--reveal"}} {
		s, e := phoneRead(testPolicy, Request{Version: Protocol, Action: "read", Args: args})
		if e != nil || s.Field == "" {
			t.Fatal(s, e)
		}
	}
	for _, args := range [][]string{{"vault", "list"}, {"item", "list"}, {"item", "get", "item"}, {"item", "get", "item", "--fields", "a,b"}, {"item", "get", "item", "--fields", "password", "--format", "json"}, {"item", "get", "item", "--fields", "password", "--otp"}, {"read", "op://v/i/f?attribute=otp"}, {"read", "op://v//f"}} {
		if _, e := phoneRead(testPolicy, Request{Version: Protocol, Action: "read", Args: args}); e == nil {
			t.Fatal("accepted unsupported request", args)
		}
	}
	c := routingConfig(t, "builder")
	c.Desktops["phone"] = Desktop{Transport: "remote-codex", Owner: "alice", Account: testPolicy.Account}
	c.DefaultDesktop = "phone"
	var out, errOut bytes.Buffer
	code := runClient(c, []string{"read", "op://v/i/f"}, strings.NewReader(""), &out, &errOut, func(_ context.Context, _ Config, route Route, r Request) Response {
		if route.Transport != "remote-codex" || r.Timeout != 300 {
			t.Fatal(route, r.Timeout)
		}
		return Response{Version: Protocol, Stdout: []byte("fake\n")}
	})
	if code != 0 || out.String() != "fake\n" {
		t.Fatal(code, out.String(), errOut.String())
	}
	called := false
	code = runClient(c, []string{"item", "create", "-"}, strings.NewReader("do not read"), &out, &errOut, func(context.Context, Config, Route, Request) Response { called = true; return Response{} })
	if code == 0 || called {
		t.Fatal("write dispatched")
	}
}
func fixtureCaller(t *testing.T, s *phoneSession) (net.Conn, <-chan struct{}) {
	t.Helper()
	l, e := net.Listen("unix", filepath.Join(t.TempDir(), "caller.sock"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			s.handleCaller(ctx, c, cancel)
		}
	}()
	c, e := net.Dial("unix", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cancel(); c.Close(); l.Close(); <-done })
	return c, done
}
func waitPending(t *testing.T, s *phoneSession) phoneRequest {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		p := s.snapshot("")
		if len(p) > 0 {
			return p[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request never pending")
	return phoneRequest{}
}
func TestPhoneCallerReleaseAckAndFormatting(t *testing.T) {
	for _, newline := range []bool{true, false} {
		t.Run(map[bool]string{true: "newline", false: "raw"}[newline], func(t *testing.T) {
			s := newPhoneSession("fixture", "alice", testPolicy.Account)
			c, done := fixtureCaller(t, s)
			args := []string{"read", "op://v/i/f"}
			if !newline {
				args = append(args, "-n")
			}
			result := make(chan Response, 1)
			go func() { result <- exchangePhone(c, Request{Version: Protocol, Action: "read", Args: args, Timeout: 2}) }()
			p := waitPending(t, s)
			if code := s.decide(p.ID, "release", "FAKE_SECRET"); code != "" {
				t.Fatal(code)
			}
			r := <-result
			want := "FAKE_SECRET"
			if newline {
				want += "\n"
			}
			if string(r.Stdout) != want || r.Error != "" {
				t.Fatal("wrong output", r.Error)
			}
			<-done
			if got := s.snapshot(p.ID)[0].State; got != "completed" {
				t.Fatal(got)
			}
			if code := s.decide(p.ID, "release", "second"); code != "request_not_pending" {
				t.Fatal(code)
			}
		})
	}
}
func TestPhoneCancellationDenialAndUncertainDelivery(t *testing.T) {
	for _, action := range []string{"cancel", "deny", "lost_ack", "expire"} {
		t.Run(action, func(t *testing.T) {
			s := newPhoneSession("fixture", "alice", testPolicy.Account)
			c, done := fixtureCaller(t, s)
			json.NewEncoder(c).Encode(Request{Version: Protocol, Action: "read", Args: []string{"read", "op://v/i/f"}, Timeout: 1})
			p := waitPending(t, s)
			switch action {
			case "cancel":
				c.Close()
			case "deny":
				s.decide(p.ID, "deny", "")
				var result Response
				json.NewDecoder(c).Decode(&result)
				if result.ErrorCode != "denied" {
					t.Fatal(result.ErrorCode)
				}
			case "lost_ack":
				s.decide(p.ID, "release", "FAKE")
				var result Response
				json.NewDecoder(c).Decode(&result)
				c.Close()
			}
			<-done
			want := map[string]string{"cancel": "cancelled", "deny": "denied", "lost_ack": "delivery_uncertain", "expire": "expired"}[action]
			if state := s.snapshot(p.ID)[0].State; state != want {
				t.Fatal(state, want)
			}
		})
	}
}
func TestPhoneLimitsIdleAndDuplicateApprovals(t *testing.T) {
	s := newPhoneSession("fixture", "alice", testPolicy.Account)
	s.idle = time.Millisecond
	s.timeLast = time.Now().Add(-time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var entries []*phoneEntry
	for i := 0; i < 16; i++ {
		e, code := s.add(ctx, phoneSelection{})
		if code != "" {
			t.Fatal(code)
		}
		entries = append(entries, e)
	}
	if _, code := s.add(ctx, phoneSelection{}); code != "queue_full" {
		t.Fatal(code)
	}
	if s.expired() {
		t.Fatal("active session expired")
	}
	id := entries[0].request.ID
	if code := s.decide(id, "release", strings.Repeat("x", phoneValueLimit+1)); code != "invalid_value" {
		t.Fatal(code)
	}
	var wg sync.WaitGroup
	results := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.decide(id, "release", "fake") }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for code := range results {
		if code == "" {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal(accepted)
	}
	for _, e := range entries {
		s.finish(e, "cancelled")
	}
	s.mu.Lock()
	s.timeLast = time.Now().Add(-time.Second)
	s.mu.Unlock()
	_ = s.snapshot("")
	if !s.expired() {
		t.Fatal("status kept session alive")
	}
	s.started = time.Now().Add(-workerLifetime)
	if _, code := s.add(ctx, phoneSelection{}); code != "session_expired" {
		t.Fatal(code)
	}
}
func TestPhoneApprovalWebSocketProtocol(t *testing.T) {
	s := newPhoneSession("fixture", "alice", testPolicy.Account)
	server := httptest.NewServer(httpHandler(s))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e, code := s.add(ctx, phoneSelection{Account: testPolicy.Account, Item: "fixture", Field: "password"})
	if code != "" {
		t.Fatal(code)
	}
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	for _, method := range []string{"list", "release", "get", "release"} {
		msg, _ := json.Marshal(approvalMessage{Version: 1, ID: method, Method: method, RequestID: e.request.ID, Value: "FAKE_VALUE"})
		if err = c.Write(ctx, websocket.MessageText, msg); err != nil {
			t.Fatal(err)
		}
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("FAKE_VALUE")) {
			t.Fatal("value leaked in approval reply")
		}
		var reply approvalReply
		if json.Unmarshal(data, &reply) != nil || reply.Version != 1 {
			t.Fatal("invalid reply")
		}
	}
	s.finish(e, "cancelled")
}
func httpHandler(s *phoneSession) http.Handler { return http.HandlerFunc(s.approval) }
