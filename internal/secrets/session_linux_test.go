package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testSessionPolicy(w *worker, idle time.Duration) sessionPolicy {
	return sessionPolicy{policy: testPolicy, idle: idle, maxAge: workerLifetime,
		start:  func() (*worker, error) { return w, nil },
		notify: func(context.Context, Request) error { return nil },
	}
}

func testWorkerFactory(t *testing.T, script string) func() (*worker, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-op")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return func() (*worker, error) {
		return startWorker(exe, []string{"-test.run=^TestWorkerProcess$"}, append(os.Environ(), "SECRETS_TEST_WORKER=1", "SECRETS_TEST_OP="+path))
	}
}

func testSession(t *testing.T, policy sessionPolicy) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "socket")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveRequests(ctx, cancel, listener, policy) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("session did not stop")
		}
	})
	return socket
}

func sessionCall(t *testing.T, socket string, r Request) Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Error(err)
		return failure("test connection failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(r); err != nil {
		t.Error(err)
		return failure("test encoding failed")
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Error(err)
		return failure("test decoding failed")
	}
	return response
}

func sessionStatus(t *testing.T, socket string) map[string]any {
	t.Helper()
	r := sessionCall(t, socket, Request{Version: Protocol, Action: "status"})
	var status map[string]any
	if err := json.Unmarshal(r.Stdout, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func awaitSessionCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("session condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSessionRotatesUnderContinuousUse(t *testing.T) {
	var notifications atomic.Int32
	socket := testSession(t, sessionPolicy{policy: testPolicy, idle: 200 * time.Millisecond, maxAge: 350 * time.Millisecond,
		start:  testWorkerFactory(t, "echo $PPID\n"),
		notify: func(context.Context, Request) error { notifications.Add(1); return nil },
	})
	first := sessionCall(t, socket, readRequest())
	if first.Exit != 0 {
		t.Fatal(first.Error)
	}
	same, rotated := false, false
	for range 10 {
		time.Sleep(50 * time.Millisecond)
		r := sessionCall(t, socket, readRequest())
		if r.Exit != 0 {
			t.Fatal(r.Error)
		}
		if string(r.Stdout) == string(first.Stdout) {
			same = true
		} else {
			rotated = true
		}
	}
	if !same || !rotated || notifications.Load() != 11 {
		t.Fatal("continuous activity failed to reuse then rotate the terminal worker")
	}
	status := sessionStatus(t, socket)
	for _, key := range []string{"idle_limit_seconds", "worker_age_seconds", "worker_lifetime_seconds", "reuse_remaining_seconds"} {
		if value, ok := status[key].(float64); !ok || value < 0 {
			t.Fatalf("missing or invalid %s: %v", key, status)
		}
	}
}

func TestExpiryPreservesActiveWriteAndQueuedDeadlines(t *testing.T) {
	dir := t.TempDir()
	release, calls := filepath.Join(dir, "release"), filepath.Join(dir, "calls")
	defer os.WriteFile(release, nil, 0600)
	var notifications atomic.Int32
	start := testWorkerFactory(t, fmt.Sprintf("echo $PPID >> %q\nwhile [ ! -e %q ]; do sleep 0.01; done\ncat >/dev/null\necho $PPID\n", calls, release))
	socket := testSession(t, sessionPolicy{policy: testPolicy, idle: 200 * time.Millisecond, maxAge: 300 * time.Millisecond, start: start,
		notify: func(context.Context, Request) error { notifications.Add(1); return nil },
	})
	active := make(chan Response, 1)
	go func() { active <- sessionCall(t, socket, writeRequest()) }()
	awaitSessionCondition(t, func() bool { _, err := os.Stat(calls); return err == nil })
	expiring := readRequest()
	expiring.Timeout = 1
	expired := make(chan Response, 1)
	go func() { expired <- sessionCall(t, socket, expiring) }()
	awaitSessionCondition(t, func() bool { return sessionStatus(t, socket)["pending"] == float64(2) })
	queued := make(chan Response, 1)
	go func() { queued <- sessionCall(t, socket, readRequest()) }()
	awaitSessionCondition(t, func() bool { return sessionStatus(t, socket)["pending"] == float64(3) })
	// A disconnected queued request must never notify or execute.
	disconnected, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer disconnected.Close()
	_ = json.NewEncoder(disconnected).Encode(readRequest())
	awaitSessionCondition(t, func() bool { return sessionStatus(t, socket)["pending"] == float64(4) })
	disconnected.Close()
	response := <-expired
	if !response.NotStarted || response.Exit == 0 {
		t.Fatalf("queued deadline not preserved: %+v", response)
	}
	if notifications.Load() != 1 {
		t.Fatal("queued requests emitted notifications")
	}
	status := sessionStatus(t, socket)
	if status["reuse_remaining_seconds"] != float64(0) {
		t.Fatalf("active write extended reuse limit: %v", status)
	}
	select {
	case <-active:
		t.Fatal("active write was interrupted at worker expiry")
	default:
	}
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	a, b := <-active, <-queued
	if a.Exit != 0 || b.Exit != 0 || string(a.Stdout) == string(b.Stdout) {
		t.Fatalf("write completion or fresh worker failed: %+v %+v", a, b)
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(string(data))) != 2 || notifications.Load() != 2 {
		t.Fatal("unexpected replay or queued notification")
	}
}

func TestStatusDoesNotKeepIdleSessionAlive(t *testing.T) {
	w := testWorker(t, "echo ready\n")
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "socket"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	policy := testSessionPolicy(w, 250*time.Millisecond)
	go func() { done <- serveRequests(ctx, cancel, listener, policy) }()
	for range 4 {
		sessionStatus(t, listener.Addr().String())
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("status kept idle session alive")
	}
}

func TestNotificationFailureNotStartedAcrossTransport(t *testing.T) {
	r := writeRequest()
	message := notStarted("desktop notification unavailable; operation not started")
	data, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fake-bridge")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nIFS= read -r request\nprintf '%s' '"+string(data)+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	received := external(context.Background(), r, path, nil, "test transport failed")
	if !received.NotStarted || received.Exit != message.Exit || received.Error != message.Error {
		t.Fatal("transport lost definitive rejection")
	}
}

func TestWorkerReplacementFailureDoesNotReplay(t *testing.T) {
	var starts int
	factory := testWorkerFactory(t, "echo ready\n")
	socket := testSession(t, sessionPolicy{policy: testPolicy, idle: time.Minute, maxAge: 100 * time.Millisecond,
		start: func() (*worker, error) {
			starts++
			if starts > 1 {
				return nil, fmt.Errorf("fake restart failure")
			}
			return factory()
		},
		notify: func(context.Context, Request) error {
			// Cross the lifetime during notification delivery, before dispatch.
			time.Sleep(150 * time.Millisecond)
			return nil
		},
	})
	r := sessionCall(t, socket, writeRequest())
	if !r.NotStarted || r.Exit == 0 || len(r.Stdout) != 0 {
		t.Fatalf("replacement failure executed operation: %+v", r)
	}
}
