package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestHistory(t *testing.T) *accessHistory {
	t.Helper()
	return &accessHistory{dir: filepath.Join(t.TempDir(), "secrets/history"), now: func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }}
}

func historyRecords(t *testing.T, h *accessHistory) []historyEvent {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dir, h.now().UTC().Format("2006-01-02")+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var records []historyEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e historyEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		records = append(records, e)
	}
	return records
}

func TestHistoryPrivacyAndRetention(t *testing.T) {
	h := newTestHistory(t)
	if err := h.append(historyEvent{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"2026-06-16.jsonl", "2026-06-17.jsonl", "unrelated"} {
		if err := os.WriteFile(filepath.Join(h.dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	h.day = ""
	r := Request{Version: Protocol, Action: "read", Args: []string{"read", "op://Vault/Item/private-field"}}
	e := testPolicy.requestHistory(r, "id")
	if err := h.append(e); err != nil {
		t.Fatal(err)
	}
	records := historyRecords(t, h)
	if len(records) != 1 || records[0].Vault != "Vault" || records[0].Item != "Item" || records[0].Operation != "read" {
		t.Fatalf("unexpected records: %+v", records)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "2026-06-16.jsonl")); !os.IsNotExist(err) {
		t.Fatal("old history retained")
	}
	for _, name := range []string{"2026-06-17.jsonl", "unrelated"} {
		if _, err := os.Stat(filepath.Join(h.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for path, mode := range map[string]os.FileMode{h.dir: 0700, filepath.Dir(h.dir): 0700, filepath.Join(h.dir, "2026-09-15.jsonl"): 0600} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("unsafe permissions: %s", path)
		}
	}
	r = Request{Version: Protocol, Action: "write", Args: []string{"item", "create", "-", "--vault=Vault", "--dry-run"}, Stdin: []byte(`{"title":"private-title","fields":[{"value":"private-value"}]}`)}
	e = testPolicy.requestHistory(r, "write")
	data, _ := json.Marshal(e)
	if !e.DryRun || e.Operation != "item create" || strings.Contains(string(data), "private") {
		t.Fatalf("unsafe write metadata: %s", data)
	}
}

func TestHistoryUnsafePathsAndConcurrentAppend(t *testing.T) {
	for _, kind := range []string{"directory_symlink", "file_symlink", "permissions", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			h := newTestHistory(t)
			if err := h.append(historyEvent{}); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(h.dir, "2026-09-15.jsonl")
			switch kind {
			case "directory_symlink":
				if err := os.Remove(h.dir); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(target), h.dir); err != nil {
					t.Fatal(err)
				}
			case "file_symlink":
				if err := os.Symlink(target, log); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, log); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(h.dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.append(historyEvent{Event: "request"}); err == nil {
				t.Fatal("unsafe path accepted")
			}
			data, _ := os.ReadFile(target)
			if string(data) != "unchanged" {
				t.Fatal("target modified")
			}
		})
	}
	h := newTestHistory(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := h.append(historyEvent{ID: fmt.Sprint(i), Event: "request"}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if len(historyRecords(t, h)) != 32 {
		t.Fatal("lost records")
	}
}

func TestSessionAccessHistory(t *testing.T) {
	for _, tc := range []struct {
		name, script, outcome          string
		reject, logFail, write, dryRun bool
	}{
		{name: "success", script: "cat >/dev/null\nprintf private-output", outcome: "success"},
		{name: "native_failure", script: "cat >/dev/null\nexit 7", outcome: "failure"},
		{name: "notification_rejected", script: "exit 0", outcome: "not_started", reject: true},
		{name: "logging_failure", script: "cat >/dev/null\nexit 0", outcome: "success", logFail: true},
		{name: "write_success", write: true, script: "cat >/dev/null\nexit 0", outcome: "success"},
		{name: "write_failure", write: true, script: "cat >/dev/null\nexit 7", outcome: "failure"},
		{name: "write_dry_run", write: true, dryRun: true, script: "cat >/dev/null\nexit 0", outcome: "success"},
		{name: "write_timeout", write: true, script: "sleep 10", outcome: "unknown"},
		{name: "timeout", script: "sleep 10", outcome: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHistory(t)
			policy := sessionPolicy{policy: testPolicy, idle: time.Minute, maxAge: workerLifetime, start: testWorkerFactory(t, tc.script), notify: func(context.Context, Request) error {
				if tc.reject {
					return fmt.Errorf("private-error")
				}
				return nil
			}, history: h.append}
			if tc.logFail {
				policy.history = func(historyEvent) error { return fmt.Errorf("private-error") }
			}
			socket := testSession(t, policy)
			r := readRequest()
			if tc.write {
				r = Request{Version: Protocol, Action: "write", Args: []string{"item", "create", "-", "--vault=Vault"}, Stdin: []byte(`{"title":"private-title"}`)}
			}
			if tc.dryRun {
				r.Args = append(r.Args, "--dry-run")
			}
			r.Timeout = 1
			response := sessionCall(t, socket, r)
			if tc.logFail {
				if response.Exit != 0 || !strings.Contains(string(response.Stderr), historyWarning) || strings.Contains(string(response.Stderr), "private-error") {
					t.Fatalf("bad warning response: %+v", response)
				}
				return
			}
			records := historyRecords(t, h)
			if len(records) != 2 || records[0].ID != records[1].ID || records[0].Event != "request" || records[1].Outcome != tc.outcome || records[1].NotificationAccepted == tc.reject {
				t.Fatalf("unexpected records: %+v", records)
			}
			data, _ := json.Marshal(records)
			if strings.Contains(string(data), "private-") {
				t.Fatal("private output in history")
			}
			sessionCall(t, socket, Request{Version: Protocol, Action: "status"})
			if len(historyRecords(t, h)) != 2 {
				t.Fatal("status logged")
			}
		})
	}
}

func TestHistoryQueuedCancellation(t *testing.T) {
	h := newTestHistory(t)
	entered, release := make(chan struct{}), make(chan struct{})
	policy := sessionPolicy{policy: testPolicy, idle: time.Minute, maxAge: workerLifetime, start: testWorkerFactory(t, "cat >/dev/null\nexit 0"), history: h.append, notify: func(ctx context.Context, r Request) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	socket := testSession(t, policy)
	done := make(chan Response, 1)
	go func() { r := readRequest(); r.Timeout = 3; done <- sessionCall(t, socket, r) }()
	<-entered
	r := readRequest()
	r.Timeout = 1
	response := sessionCall(t, socket, r)
	close(release)
	<-done
	if !response.NotStarted {
		t.Fatal("queued request started")
	}
	records := historyRecords(t, h)
	if len(records) != 4 {
		t.Fatalf("expected two pairs, got %d", len(records))
	}
	found := false
	for _, e := range records {
		if e.Outcome == "not_started" {
			found = true
			if e.NotificationAccepted || e.Reason != "queued_cancelled" {
				t.Fatalf("bad queued outcome: %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("missing queued outcome")
	}
}

func TestHistoryDayRollover(t *testing.T) {
	h := newTestHistory(t)
	if err := h.append(historyEvent{ID: "unfinished", Event: "request"}); err != nil {
		t.Fatal(err)
	}
	records := historyRecords(t, h)
	if len(records) != 1 || records[0].Outcome != "" {
		t.Fatal("incomplete request acquired an outcome")
	}
	oldPath := filepath.Join(h.dir, "2026-09-15.jsonl")
	h.now = func() time.Time { return time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC) }
	if err := h.append(historyEvent{Event: "request"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatal("rollover did not remove expired history")
	}
}
