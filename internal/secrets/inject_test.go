//go:build linux || (darwin && arm64)

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func injectRequest(template string) Request {
	return Request{Version: Protocol, Action: "read", Args: []string{"inject"}, Stdin: []byte(template)}
}

func TestInjectPolicyBoundary(t *testing.T) {
	for _, template := range []string{"", "literal\ntext", "{{ op://Private/Item/field }}\n"} {
		r := injectRequest(template)
		args, err := testPolicy.Validate(r)
		if err != nil || !reflect.DeepEqual(args, []string{"inject", "--account=" + testPolicy.Account}) {
			t.Fatalf("inject rejected or account not pinned: %v %v", args, err)
		}
		r.Args = args
		if _, err := testPolicy.Validate(r); err != nil {
			t.Fatal("pinned request failed revalidation")
		}
		data, _ := json.Marshal(r)
		if _, err := decodeRequest(bytes.NewReader(data), testPolicy); err != nil {
			t.Fatal("wire validation rejected inject")
		}
	}
	for _, args := range [][]string{
		{"inject", "private-file"}, {"inject", "-"}, {"inject", "--in-file=private-file"},
		{"inject", "--out-file=private-file"}, {"inject", "-i", "private-file"},
		{"inject", "-o", "private-file"}, {"inject", "--file-mode=0600"},
		{"inject", "--force"}, {"inject", "--format=json"},
		{"inject", "--account=other.1password.com"}, {"inject", "--env-file=private-file"},
		{"read", "op://Vault/Item/field"}, {"item", "get", "id"},
	} {
		r := injectRequest("private-template")
		r.Args = args
		if _, err := testPolicy.Validate(r); err == nil {
			t.Fatalf("unsafe stdin operation accepted: %v", args)
		}
	}
	for _, action := range []string{"write", "status", "doctor", "stop"} {
		r := injectRequest(`{"title":"private-template"}`)
		r.Action = action
		if _, err := testPolicy.Validate(r); err == nil {
			t.Fatalf("inject accepted as %s", action)
		}
	}
}

type failedTemplateReader struct{}

func (failedTemplateReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("private-input-error")
}

func TestInjectRejectsInputBeforeDispatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input interface{ Read([]byte) (int, error) }
	}{
		{"read_error", failedTemplateReader{}},
		{"raw_limit", strings.NewReader(strings.Repeat("x", MaxRequest+1))},
		{"encoded_limit", strings.NewReader(strings.Repeat("x", MaxRequest*3/4))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			calls := 0
			code := runClient(routingConfig(t, "builder"), []string{"inject"}, tc.input, &out, &stderr,
				func(context.Context, Config, Route, Request) Response { calls++; return Response{Version: Protocol} })
			if code == 0 || calls != 0 || out.Len() != 0 || strings.Contains(stderr.String(), "private-") {
				t.Fatal("invalid input dispatched or private input leaked")
			}
		})
	}
}

func TestInjectClientAndNativeForwarding(t *testing.T) {
	for _, template := range []string{
		"", "literal\nsecond line\n",
		"A={{ op://Vault/Item/field }}\nB={{ op://Other/Item/field }}\nC={{ op://Vault/Item/field }}\n",
	} {
		t.Run(fmt.Sprintf("bytes_%d", len(template)), func(t *testing.T) {
			dir := t.TempDir()
			callsFile, inputFile := filepath.Join(dir, "calls"), filepath.Join(dir, "input")
			script := fmt.Sprintf(`test "$#" -eq 2 || exit 8
test "$1" = inject || exit 9
test "$2" = --account=example.1password.com || exit 10
test -p /dev/stdin || exit 11
printf 'call\n' >> %q
cat > %q
printf 'fake rendered value\nsecond line\n'
`, callsFile, inputFile)
			socket := testSession(t, sessionPolicy{policy: testPolicy, idle: time.Minute, maxAge: workerLifetime, start: testWorkerFactory(t, script)})
			var out, stderr bytes.Buffer
			calls := 0
			code := runClient(routingConfig(t, "builder"), []string{"--desktop", "workstation", "--timeout", "45", "inject"}, strings.NewReader(template), &out, &stderr,
				func(_ context.Context, _ Config, route Route, r Request) Response {
					calls++
					if route.Desktop != "workstation" || r.Timeout != 45 || r.Action != "read" || string(r.Stdin) != template {
						t.Fatal("route, timeout, or template changed")
					}
					return sessionCall(t, socket, r)
				})
			if code != 0 || calls != 1 || out.String() != "fake rendered value\nsecond line\n" {
				t.Fatalf("bulk request failed: exit=%d calls=%d stderr=%s", code, calls, &stderr)
			}
			input, err := os.ReadFile(inputFile)
			if err != nil || string(input) != template {
				t.Fatal("native stdin changed")
			}
			invocations, err := os.ReadFile(callsFile)
			if err != nil || string(invocations) != "call\n" {
				t.Fatal("expected exactly one native invocation")
			}
			if strings.Contains(stderr.String(), "op://") || strings.Contains(stderr.String(), "fake rendered") {
				t.Fatal("wrapper diagnostics exposed template or values")
			}
		})
	}
}

func TestInjectFailureDiscardsNativeStdout(t *testing.T) {
	for _, tc := range []struct{ name, script string }{
		{"native_exit", "cat >/dev/null\nprintf partial-value\nprintf native-diagnostic >&2\nexit 7\n"},
		{"timeout", "cat >/dev/null\nprintf partial-value\nsleep 30\n"},
		{"output_limit", "cat >/dev/null\nprintf partial-value\nhead -c 18000000 /dev/zero\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := testWorker(t, tc.script)
			r := injectRequest("{{ op://Private/Item/field }}")
			r.Timeout = 1
			response := workerCall(t, w, r)
			if response.Exit == 0 || len(response.Stdout) != 0 {
				t.Fatal("failed inject released partial stdout")
			}
			if tc.name == "native_exit" && (response.Exit != 7 || string(response.Stderr) != "native-diagnostic" || response.Error != "") {
				t.Fatal("native stderr or exit status changed")
			}
		})
	}
}

func TestInjectClientDiscardsFailedResponse(t *testing.T) {
	for _, response := range []Response{
		{Version: Protocol, Exit: 7, Stdout: []byte("partial-value"), Stderr: []byte("native-diagnostic")},
		{Version: Protocol, Exit: 1, Stdout: []byte("partial-value"), Error: "transport failed"},
	} {
		var out, stderr bytes.Buffer
		code := runClient(routingConfig(t, "builder"), []string{"inject"}, strings.NewReader("private-template"), &out, &stderr,
			func(context.Context, Config, Route, Request) Response { return response })
		if code != response.Exit || out.Len() != 0 || strings.Contains(stderr.String(), "private-template") {
			t.Fatal("failed response released template stdout")
		}
	}
}

func TestInjectHistoryPrivacy(t *testing.T) {
	var mu sync.Mutex
	var events []historyEvent
	policy := sessionPolicy{policy: testPolicy, idle: time.Minute, maxAge: workerLifetime,
		start: testWorkerFactory(t, "cat >/dev/null\nprintf private-value\n"),
		history: func(e historyEvent) error {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, e)
			return nil
		},
	}
	socket := testSession(t, policy)
	response := sessionCall(t, socket, injectRequest("private-template {{ op://private-vault/private-item/private-field }}"))
	mu.Lock()
	defer mu.Unlock()
	if response.Exit != 0 || len(events) != 2 || events[0].ID != events[1].ID || events[0].Operation != "inject" || events[1].Outcome != "success" {
		t.Fatal("missing inject request/outcome metadata")
	}
	data, _ := json.Marshal(events)
	if strings.Contains(string(data), "private-") || events[0].Vault != "" || events[0].Item != "" {
		t.Fatal("history exposed template or values")
	}
}

func TestInjectQueuedTimeoutAndDisconnect(t *testing.T) {
	for _, mode := range []string{"queued_timeout", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			entered, release := filepath.Join(dir, "entered"), filepath.Join(dir, "release")
			script := fmt.Sprintf(`case "$1" in
inject) printf started > %q; printf partial-value; while [ ! -e %q ]; do sleep 0.01; done ;;
*) printf ready ;;
esac
`, entered, release)
			socket := testSession(t, sessionPolicy{policy: testPolicy, idle: time.Minute, maxAge: workerLifetime, start: testWorkerFactory(t, script)})
			conn, err := net.Dial("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := json.NewEncoder(conn).Encode(injectRequest("private-template")); err != nil {
				t.Fatal(err)
			}
			awaitSessionCondition(t, func() bool { _, err := os.Stat(entered); return err == nil })
			if mode == "queued_timeout" {
				r := injectRequest("queued-template")
				r.Timeout = 1
				response := sessionCall(t, socket, r)
				if !response.NotStarted || len(response.Stdout) != 0 {
					t.Fatal("queued inject was started")
				}
				if err := os.WriteFile(release, nil, 0600); err != nil {
					t.Fatal(err)
				}
				var responseActive Response
				if err := json.NewDecoder(conn).Decode(&responseActive); err != nil {
					t.Fatal(err)
				}
			} else {
				conn.Close()
			}
			response := sessionCall(t, socket, readRequest())
			if response.Exit != 0 || string(response.Stdout) != "ready" {
				t.Fatal("inject blocked the next operation")
			}
		})
	}
}
