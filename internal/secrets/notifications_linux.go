package secrets

import (
	"context"
	"fmt"
	"html"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/godbus/dbus/v5"
)

const notificationService = "org.freedesktop.Notifications"
const notificationPath dbus.ObjectPath = "/org/freedesktop/Notifications"
const notificationTimeout = 2 * time.Second

// The socket is derived from the configured desktop UID, never caller input or
// the caller's environment. A private socket can be supplied by tests.
type desktopNotifications struct {
	socket string
	policy Policy
}

func (n desktopNotifications) connect(ctx context.Context) (*dbus.Conn, error) {
	transport, err := (&net.Dialer{}).DialContext(ctx, "unix", n.socket)
	if err != nil {
		return nil, err
	}
	// Bound authentication and Hello as well as method calls. ConnectUnix's
	// authentication handshake otherwise has no explicit timeout.
	if deadline, ok := ctx.Deadline(); ok {
		_ = transport.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { transport.Close() })
	defer stop()
	conn, err := dbus.ConnectUnix(transport.(*net.UnixConn), dbus.WithContext(ctx))
	if err != nil {
		transport.Close()
	}
	return conn, err
}

func (n desktopNotifications) available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, notificationTimeout)
	defer cancel()
	conn, err := n.connect(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	var owned bool
	// NameHasOwner neither activates a desktop service nor sends a banner.
	err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, notificationService).Store(&owned)
	return err == nil && owned
}

func (n desktopNotifications) notify(ctx context.Context, r Request) error {
	body, err := n.policy.notificationBody(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, notificationTimeout)
	defer cancel()
	conn, err := n.connect(ctx)
	if err != nil {
		return fmt.Errorf("desktop notification service unavailable")
	}
	defer conn.Close()
	var id uint32
	err = conn.Object(notificationService, notificationPath).CallWithContext(ctx,
		notificationService+".Notify", dbus.FlagNoAutoStart,
		"op-bridge", uint32(0), "dialog-password",
		"op-bridge: access requested", body, []string{},
		map[string]dbus.Variant{"transient": dbus.MakeVariant(true), "urgency": dbus.MakeVariant(byte(1))}, int32(5000)).Store(&id)
	if err != nil || id == 0 {
		return fmt.Errorf("desktop notification was not accepted")
	}
	return nil
}

// Only validated operation names and explicit target identifiers are displayed.
// In particular, never inspect templates or forward args, field selectors, or
// native output wholesale to the notification service.
func (p Policy) notificationBody(r Request) (string, error) {
	args, err := p.Validate(r)
	if err != nil || (r.Action != "read" && r.Action != "write") {
		return "", fmt.Errorf("invalid notification request")
	}
	n := 2
	operation := "read"
	if args[0] == "read" {
		n = 1
	} else {
		operation = strings.Join(args[:2], " ")
	}
	var vault, item string
	for _, arg := range args[n:] {
		if value, ok := strings.CutPrefix(arg, "--vault="); ok {
			vault = value
		} else if arg == "--dry-run" {
			operation += " (dry run)"
		} else if !strings.HasPrefix(arg, "-") {
			item = arg
		}
	}
	if args[0] == "read" {
		parts := strings.SplitN(strings.TrimPrefix(item, "op://"), "/", 3)
		vault, item = parts[0], parts[1]
	}
	body := operation
	if vault != "" {
		body += "\nVault: " + notificationIdentifier(vault)
	}
	if item != "" {
		body += "\nItem: " + notificationIdentifier(item)
	}
	return body, nil
}

func notificationIdentifier(s string) string {
	runes := make([]rune, 0, 160)
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if len(runes) == 160 {
			runes = append(runes, '…')
			break
		}
		runes = append(runes, r)
	}
	return html.EscapeString(string(runes))
}
