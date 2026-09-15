package secrets

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type notificationCall struct {
	app, icon, summary, body string
	replaces                 uint32
	actions                  []string
	hints                    map[string]dbus.Variant
	expiry                   int32
}

type fakeNotifications struct {
	calls  chan notificationCall
	reject bool
	zeroID bool
	wait   <-chan struct{}
}

func (f *fakeNotifications) Notify(app string, replaces uint32, icon, summary, body string, actions []string, hints map[string]dbus.Variant, expiry int32) (uint32, *dbus.Error) {
	f.calls <- notificationCall{app, icon, summary, body, replaces, actions, hints, expiry}
	if f.wait != nil {
		<-f.wait
	}
	if f.reject {
		return 0, dbus.MakeFailedError(fmt.Errorf("fake rejection with private details"))
	}
	if f.zeroID {
		return 0, nil
	}
	return 42, nil
}

// All D-Bus tests use a disposable bus and never connect to a desktop bus.
func testNotificationBus(t *testing.T, service *fakeNotifications) desktopNotifications {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "bus")
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--address=unix:path="+socket, "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	n := desktopNotifications{policy: testPolicy, socket: socket}
	if service != nil {
		conn, err := dbus.Connect("unix:path=" + socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		if err := conn.Export(service, notificationPath, notificationService); err != nil {
			t.Fatal(err)
		}
		reply, err := conn.RequestName(notificationService, dbus.NameFlagDoNotQueue)
		if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
			t.Fatalf("own notification service: %v %v", reply, err)
		}
	}
	return n
}

func TestNotificationTargets(t *testing.T) {
	for _, tc := range []struct {
		args                []string
		action, input, want string
	}{
		{[]string{"read", "op://Vault/Item/SECRET_FIELD"}, "read", "", "read\nVault: Vault\nItem: Item"},
		{[]string{"item", "get", "<Item>&\t\u202e", "--vault=Vault", "--fields=SECRET_FIELD", "--otp"}, "read", "", "item get\nVault: Vault\nItem: &lt;Item&gt;&amp;"},
		{[]string{"vault", "list"}, "read", "", "vault list"},
		{[]string{"item", "list", "--tags=SECRET_TAG", "--vault", "Vault"}, "read", "", "item list\nVault: Vault"},
		{[]string{"item", "create", "-", "--vault=Vault", "--dry-run"}, "write", `{"title":"SECRET_TITLE","fields":[{"value":"SECRET_VALUE"}]}`, "item create (dry run)\nVault: Vault"},
		{[]string{"item", "edit", "ID", "--vault", "Vault"}, "write", `{"title":"SECRET_TITLE"}`, "item edit\nVault: Vault\nItem: ID"},
	} {
		r := Request{Version: Protocol, Action: tc.action, Args: tc.args, Stdin: []byte(tc.input)}
		body, err := testPolicy.notificationBody(r)
		if err != nil || body != tc.want {
			t.Fatalf("notification: %q, %v; want %q", body, err, tc.want)
		}
		if strings.Contains(body, "SECRET_") {
			t.Fatal("private data in notification")
		}
	}
	if got := notificationIdentifier(strings.Repeat("界", 200)); got != strings.Repeat("界", 160)+"…" {
		t.Fatal("identifier not bounded by runes")
	}
	if _, err := testPolicy.notificationBody(Request{Version: Protocol, Action: "status"}); err == nil {
		t.Fatal("notified status")
	}
}

func TestDesktopNotifications(t *testing.T) {
	f := &fakeNotifications{calls: make(chan notificationCall, 4)}
	n := testNotificationBus(t, f)
	if !n.available(context.Background()) {
		t.Fatal("service not detected")
	}
	if len(f.calls) != 0 {
		t.Fatal("doctor sent a notification")
	}
	for range 2 {
		if err := n.notify(context.Background(), readRequest()); err != nil {
			t.Fatal(err)
		}
		call := <-f.calls
		if call.app != "op-bridge" || call.summary != "op-bridge: access requested" || call.body != "vault list" || call.replaces != 0 || call.expiry != 5000 || len(call.actions) != 0 || call.hints["transient"].Value() != true {
			t.Fatalf("unexpected notification: %+v", call)
		}
	}
}

func TestNotificationDeliveryFailures(t *testing.T) {
	for _, kind := range []string{"missing", "rejected", "zero-id", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			f := &fakeNotifications{calls: make(chan notificationCall, 4), reject: kind == "rejected", zeroID: kind == "zero-id"}
			if kind == "missing" {
				f = nil
			}
			if kind == "timeout" {
				release := make(chan struct{})
				f.wait = release
				defer close(release)
			}
			n := testNotificationBus(t, f)
			if kind == "missing" && n.available(context.Background()) {
				t.Fatal("absent service reported available")
			}
			started := time.Now()
			if err := n.notify(context.Background(), readRequest()); err == nil || strings.Contains(err.Error(), "private details") {
				t.Fatalf("unexpected error: %v", err)
			}
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("notification exceeded two-second deadline: %v", elapsed)
			}
		})
	}
}

func TestNotificationBeforeCLIAndRejectedWrite(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "cli-started")
			release := make(chan struct{})
			defer close(release)
			f := &fakeNotifications{calls: make(chan notificationCall, 4), reject: reject, wait: release}
			n := testNotificationBus(t, f)
			policy := sessionPolicy{policy: testPolicy, idle: time.Minute, maxAge: workerLifetime, start: testWorkerFactory(t, fmt.Sprintf("printf started > %q\ncat\n", marker)), notify: n.notify}
			socket := testSession(t, policy)
			result := make(chan Response, 1)
			go func() { result <- sessionCall(t, socket, writeRequest()) }()
			select {
			case <-f.calls:
			case <-time.After(3 * time.Second):
				t.Fatal("no notification")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("CLI started before notification acceptance")
			}
			// Let the fake service acknowledge or reject the banner.
			// Send rather than close: the deferred close also releases a timed-out handler.
			release <- struct{}{}
			response := <-result
			if reject {
				encoded := uncertainWrite(writeRequest(), response)
				if !encoded.NotStarted || encoded.Exit == 0 || strings.Contains(encoded.Error, "unknown") {
					t.Fatalf("rejected write is not definitive: %+v", encoded)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("rejected notification executed CLI")
				}
			} else if response.Exit != 0 || string(response.Stdout) != string(writeRequest().Stdin) {
				t.Fatalf("write failed: %+v", response)
			}
		})
	}
}

func TestNotificationConnectionHandshakeDeadline(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "stalled-bus")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = (desktopNotifications{policy: testPolicy, socket: socket}).notify(ctx, readRequest())
	conn := <-accepted
	if conn != nil {
		conn.Close()
	}
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("stalled D-Bus authentication did not respect deadline: %v", err)
	}
}
