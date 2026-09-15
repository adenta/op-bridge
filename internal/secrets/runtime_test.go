//go:build linux

package secrets

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Only the test executable has this entry point. Production accepts no binary override.
func TestWorkerProcess(t *testing.T) {
	if os.Getenv("SECRETS_TEST_WORKER") != "1" {
		return
	}
	os.Exit(runWorker(os.Stdin, os.Stdout, os.Getenv("SECRETS_TEST_OP"), os.Environ(), testPolicy))
}

func testWorker(t *testing.T, script string) *worker {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-op")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	w, err := startWorker(exe, []string{"-test.run=^TestWorkerProcess$"}, append(os.Environ(), "SECRETS_TEST_WORKER=1", "SECRETS_TEST_OP="+path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	return w
}

func workerCall(t *testing.T, w *worker, r Request) Response {
	t.Helper()
	if _, err := w.send(r); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := w.decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response
}

func readRequest() Request {
	return Request{Version: Protocol, Action: "read", Args: []string{"vault", "list", "--format=json"}}
}

func TestCancelOnDisconnect(t *testing.T) {
	for _, readError := range []error{nil, io.ErrUnexpectedEOF} {
		t.Run(fmt.Sprint(readError), func(t *testing.T) {
			input, sender := io.Pipe()
			defer input.Close()
			defer sender.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go cancelOnDisconnect(input, cancel)
			for _, chunk := range []string{"\n", " \r\n"} {
				if _, err := io.WriteString(sender, chunk); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("trailing bytes cancelled an open transport")
			case <-time.After(20 * time.Millisecond):
			}
			_ = sender.CloseWithError(readError)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("disconnect did not cancel the request")
			}
		})
	}
}

func TestCLIStartupErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-op")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, tc := range []struct {
		name, program, want string
		ctx                 context.Context
	}{
		{"cancelled", path, "1Password request cancelled before CLI startup", cancelled},
		{"expired", path, "1Password request timed out before CLI startup", expired},
		{"missing", path + ".missing", syscall.ENOENT.Error(), context.Background()},
		{"permission", path, syscall.EACCES.Error(), context.Background()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := execute(tc.ctx, tc.program, []string{"private-argument"}, []string{"PRIVATE=private-environment"}, []byte("private-input"))
			if r.Exit != 1 || r.Version != Protocol || len(r.Stdout)+len(r.Stderr) != 0 || !strings.Contains(r.Error, tc.want) {
				t.Fatalf("unexpected startup result: %+v", r)
			}
			for _, sentinel := range []string{"private-argument", "private-environment", "private-input"} {
				if strings.Contains(r.Error, sentinel) {
					t.Fatal("startup diagnostic exposed request contents")
				}
			}
			write := uncertainWrite(writeRequest(), r)
			if !strings.Contains(write.Error, "write result is unknown") {
				t.Fatal("startup diagnostic lost write uncertainty")
			}
		})
	}
}

func TestWorkerRecoversAfterStartupFailure(t *testing.T) {
	w := testWorker(t, "printf ready\n")
	var path string
	for _, entry := range w.cmd.Env {
		if value, ok := strings.CutPrefix(entry, "SECRETS_TEST_OP="); ok {
			path = value
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if r := workerCall(t, w, readRequest()); r.Exit != 1 || !strings.Contains(r.Error, syscall.EACCES.Error()) {
		t.Fatalf("expected launch permission failure: %+v", r)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if r := workerCall(t, w, readRequest()); r.Exit != 0 || string(r.Stdout) != "ready" {
		t.Fatalf("worker did not recover after launch failure: %+v", r)
	}
}

func TestWorkerItemListTimeoutAndFormat(t *testing.T) {
	w := testWorker(t, "printf '%s\\n' \"$@\"\n")
	for _, timeout := range []int{0, 45, 46, 120} {
		for _, format := range [][]string{{"--format=json"}, {"--format", "json"}} {
			t.Run(fmt.Sprintf("timeout=%d/format=%s", timeout, strings.Join(format, " ")), func(t *testing.T) {
				r := Request{Version: Protocol, Action: "read", Timeout: timeout, Args: append([]string{"item", "list", "--vault", "test-vault"}, format...)}
				response := workerCall(t, w, r)
				want := "item\nlist\n--account=" + testPolicy.Account + "\n--vault=test-vault\n--format=json\n"
				if response.Exit != 0 || string(response.Stdout) != want {
					t.Fatalf("request variant changed native execution: %+v", response)
				}
			})
		}
	}
}

func TestTimeoutKillsCLIAndKeepsWorker(t *testing.T) {
	w := testWorker(t, `case "$1" in
read) trap '' TERM; while :; do sleep 1; done ;;
*) printf 'ready' ;;
esac
`)
	r := Request{Version: Protocol, Action: "read", Timeout: 1, Args: []string{"read", "op://v/i/f"}}
	start := time.Now()
	result := workerCall(t, w, r)
	if result.Exit == 0 || time.Since(start) > 5*time.Second {
		t.Fatal("timeout did not stop CLI")
	}
	if next := workerCall(t, w, readRequest()); next.Exit != 0 || string(next.Stdout) != "ready" {
		t.Fatal("worker did not recover")
	}
}

func TestLateCancellationCannotAffectNextRequest(t *testing.T) {
	w := testWorker(t, "sleep 0.05\nprintf 'ready'\n")
	workerCall(t, w, readRequest())
	oldID := w.nextID
	if _, err := w.send(readRequest()); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(w.in).Encode(workerMessage{ID: oldID, Cancel: true}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := w.decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Exit != 0 || string(response.Stdout) != "ready" {
		t.Fatal("late cancellation affected next request")
	}
}

func TestExternalKeepsRequestPipeOpen(t *testing.T) {
	path, _ := os.Executable()
	t.Setenv("SECRETS_TEST_PIPE", "1")
	for _, request := range []Request{readRequest(), writeRequest()} {
		r := external(context.Background(), request, path, []string{"-test.run=^TestBridgePipeProcess$"}, "bridge failed")
		if r.Exit != 0 {
			t.Fatal(r.Error)
		}
	}
}

func TestBridgePipeProcess(t *testing.T) {
	if os.Getenv("SECRETS_TEST_PIPE") != "1" {
		return
	}
	r := bufio.NewReader(os.Stdin)
	if _, err := r.ReadString('\n'); err != nil {
		os.Exit(2)
	}
	closed := make(chan struct{})
	go func() { _, _ = r.ReadByte(); close(closed) }()
	select {
	case <-closed:
		os.Exit(3)
	case <-time.After(100 * time.Millisecond):
		_ = json.NewEncoder(os.Stdout).Encode(Response{Version: Protocol, Exit: 0})
		os.Exit(0)
	}
}

func TestOutputBound(t *testing.T) {
	w := testWorker(t, "head -c 18000000 /dev/zero\n")
	r := workerCall(t, w, readRequest())
	if r.Exit == 0 || len(r.Stdout) > MaxOutput {
		t.Fatal("output bound not enforced")
	}
}

func TestSessionDisconnectAndIdle(t *testing.T) {
	w := testWorker(t, `case "$1" in
read) sleep 30 ;;
item) cat ;;
*) printf 'ready' ;;
esac
`)
	socket := filepath.Join(t.TempDir(), "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveRequests(ctx, cancel, listener, testSessionPolicy(w, 400*time.Millisecond)) }()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(conn).Encode(Request{Version: Protocol, Action: "read", Args: []string{"read", "op://v/i/f"}})
	time.Sleep(150 * time.Millisecond)
	conn.Close()
	conn, err = net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	json.NewEncoder(conn).Encode(readRequest())
	var r Response
	if err := json.NewDecoder(conn).Decode(&r); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if r.Exit != 0 || string(r.Stdout) != "ready" {
		t.Fatal("disconnected request blocked next request")
	}
	conn, err = net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	write := writeRequest()
	json.NewEncoder(conn).Encode(write)
	if err := json.NewDecoder(conn).Decode(&r); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if r.Exit != 0 || !bytes.Equal(r.Stdout, write.Stdin) {
		t.Fatal("session did not carry JSON to the native write process")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle session did not expire")
	}
}

// A stream can deliver the encoder's final newline after Decode has returned.
// The open connection still belongs to this request; that byte is not EOF.
func TestSessionDelayedRequestNewline(t *testing.T) {
	dir := t.TempDir()
	started, release := filepath.Join(dir, "started"), filepath.Join(dir, "release")
	w := testWorker(t, fmt.Sprintf("printf started > %q\nwhile [ ! -e %q ]; do sleep 0.01; done\nprintf ready\n", started, release))
	listener, err := net.Listen("unix", filepath.Join(dir, "socket"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveRequests(ctx, cancel, listener, testSessionPolicy(w, time.Minute)) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	conn, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := Request{Version: Protocol, Action: "read", Timeout: 45, Args: []string{"item", "list", "--vault", strings.Repeat("v", 26), "--format=json"}}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 128 {
		t.Fatalf("expected the observed 128-byte request shape, got %d", len(data))
	}
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fake CLI did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := conn.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	// Give the disconnect watcher a chance to observe the delayed byte before
	// allowing the native process to finish normally.
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Exit != 0 || string(response.Stdout) != "ready" {
		t.Fatalf("delayed newline cancelled the request: %+v", response)
	}
}

func TestDecoderRejectsUntrustedRequests(t *testing.T) {
	for _, input := range []string{fmt.Sprintf(`{"version":%d,"action":"read","args":["signin"]}`, Protocol), fmt.Sprintf(`{"version":%d,"action":"status","env":{"PATH":"evil"}}`, Protocol), strings.Repeat(" ", MaxRequest) + `{}`} {
		if _, err := decodeRequest(strings.NewReader(input), testPolicy); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}

func TestWritePipeAndNativeFailure(t *testing.T) {
	w := testWorker(t, `[ -p /dev/stdin ] || exit 9
cat
printf 'native diagnostic' >&2
exit 7
`)
	for _, operation := range []string{"create", "edit"} {
		r := writeRequest()
		if operation == "edit" {
			r.Args = []string{"item", "edit", "item-id", "--vault=Test"}
		}
		response := workerCall(t, w, r)
		if response.Exit != 7 || !bytes.Equal(response.Stdout, r.Stdin) || string(response.Stderr) != "native diagnostic" || response.Error != "" {
			t.Fatal("JSON pipe or native result was not preserved")
		}
	}
}

func TestWriteInputLimits(t *testing.T) {
	for _, input := range []string{"", "{invalid", strings.Repeat(" ", MaxRequest+1)} {
		r := writeRequest()
		if err := readWriteInput(&r, strings.NewReader(input), testPolicy); err == nil {
			t.Fatal("invalid or oversized input accepted")
		}
	}
}

// Exercise the same input reader with Node's socket-backed stdin and a shell
// pipe. The internal request/response transport must stay separate from it.
func TestWriteInputProcess(t *testing.T) {
	if os.Getenv("SECRETS_TEST_INPUT") != "1" {
		return
	}
	r := writeRequest()
	if err := readWriteInput(&r, os.Stdin, testPolicy); err != nil {
		os.Exit(2)
	}
	w := testWorker(t, "[ -p /dev/stdin ] || exit 9\ncat\n")
	response := workerCall(t, w, r)
	w.close()
	if response.Exit != 0 || !bytes.Equal(response.Stdout, r.Stdin) {
		os.Exit(3)
	}
	os.Stdout.Write(response.Stdout)
	os.Exit(0)
}

func TestShellAndNodeWriteInput(t *testing.T) {
	exe, _ := os.Executable()
	input := writeRequest().Stdin
	t.Setenv("SECRETS_TEST_INPUT", "1")
	for _, program := range []string{"bash", "node"} {
		t.Run(program, func(t *testing.T) {
			path, err := exec.LookPath(program)
			if err != nil {
				t.Skipf("%s is unavailable", program)
			}
			var cmd *exec.Cmd
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if program == "bash" {
				cmd = exec.CommandContext(ctx, path, "-c", `cat | "$1" -test.run=^TestWriteInputProcess$`, "test-input", exe)
			} else {
				cmd = exec.CommandContext(ctx, path, "-e", `const r = require('child_process').spawnSync(process.argv[1], ['-test.run=^TestWriteInputProcess$'], {input: require('fs').readFileSync(0), env: process.env, timeout: 5000}); process.stdout.write(r.stdout); process.exit(r.status ?? 1);`, exe)
			}
			cmd.WaitDelay = time.Second
			cmd.Stdin = bytes.NewReader(input)
			out, err := cmd.Output()
			if err != nil || !bytes.Equal(out, input) {
				t.Fatalf("%s input failed: %v", program, err)
			}
		})
	}
}

func TestWriteTimeoutAndDisconnect(t *testing.T) {
	w := testWorker(t, `case "$1" in
item) cat >/dev/null; sleep 30 ;;
*) printf ready ;;
esac
`)
	r := writeRequest()
	r.Timeout = 1
	response := workerCall(t, w, r)
	if response.Exit == 0 || !strings.Contains(response.Error, "write result is unknown") {
		t.Fatal("write timeout did not report an uncertain result")
	}
	if response = workerCall(t, w, readRequest()); response.Exit != 0 || string(response.Stdout) != "ready" {
		t.Fatal("worker did not recover after write timeout")
	}
	path := filepath.Join(t.TempDir(), "disconnect")
	marker := filepath.Join(filepath.Dir(path), "calls")
	script := "#!/bin/sh\nIFS= read -r request\nprintf x >> \"$1\"\nexit 255\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	response = external(context.Background(), r, path, []string{marker}, "connection lost")
	count, _ := os.ReadFile(marker)
	if response.Exit == 0 || !strings.Contains(response.Error, "write result is unknown") || string(count) != "x" {
		t.Fatal("disconnected write was retried or reported as definite failure")
	}
}

func TestProtocolMismatchAndConfigVersion(t *testing.T) {
	if ConfigVersion != 3 {
		t.Fatal("routing configuration requires a coordinated upgrade")
	}
	_, err := decodeRequest(strings.NewReader(`{"version":1,"action":"status"}`), testPolicy)
	if err == nil || !strings.Contains(err.Error(), "protocol mismatch") {
		t.Fatal("old client must receive an upgrade message")
	}
}
