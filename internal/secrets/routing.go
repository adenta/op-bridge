//go:build linux

package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type Route struct {
	Machine   string `json:"execution_host"`
	Desktop   string `json:"desktop"`
	Transport string `json:"transport"`
	Source    string `json:"source"`
}

func selectRoute(c Config, desktop string) (Route, error) {
	r := Route{Machine: c.Machine, Desktop: c.DefaultDesktop, Source: "default"}
	if desktop != "" {
		r.Desktop, r.Source = desktop, "override"
	}
	d, ok := c.Desktops[r.Desktop]
	if !ok {
		names := make([]string, 0, len(c.Desktops))
		for name := range c.Desktops {
			names = append(names, name)
		}
		sort.Strings(names)
		return r, fmt.Errorf("unsupported desktop; configured destinations: %s", strings.Join(names, ", "))
	}
	r.Transport = d.Transport
	return r, nil
}

// Global options precede the operation and may appear in either order.
func clientOptions(args []string) (rest []string, desktop string, timeout int, err error) {
	seen := map[string]bool{}
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		name, value, inline := strings.Cut(args[0], "=")
		if name != "--desktop" && name != "--timeout" {
			return nil, "", 0, fmt.Errorf("unsupported global option")
		}
		if seen[name] {
			return nil, "", 0, fmt.Errorf("duplicate %s option", name)
		}
		seen[name] = true
		args = args[1:]
		if !inline && len(args) > 0 {
			value, args = args[0], args[1:]
		}
		if value == "" {
			return nil, "", 0, fmt.Errorf("%s requires a value", name)
		}
		if name == "--desktop" {
			desktop = value
		} else {
			timeout, err = strconv.Atoi(value)
			if err != nil || timeout < 1 || timeout > 300 {
				return nil, "", 0, fmt.Errorf("invalid timeout; use 1 to 300 seconds")
			}
		}
	}
	return args, desktop, timeout, nil
}

type dispatcher func(context.Context, Config, Route, Request) Response

func runClient(c Config, args []string, input io.Reader, output, errorOutput io.Writer, send dispatcher) int {
	args, desktop, timeout, err := clientOptions(args)
	if err != nil {
		fmt.Fprintln(errorOutput, err)
		return 1
	}
	route, err := selectRoute(c, desktop)
	if err != nil {
		fmt.Fprintln(errorOutput, err)
		return 1
	}
	if len(args) > 0 && args[0] == "route" {
		if len(args) < 2 || args[1] != "show" {
			fmt.Fprintln(errorOutput, "usage: route show [--format=json]")
			return 1
		}
		switch strings.Join(args[2:], " ") {
		case "", "--format=human-readable", "--format human-readable":
			_, err = fmt.Fprintf(output, "Execution host: %s\nApproval desktop: %s\nTransport: %s\nSelection: %s\n", route.Machine, route.Desktop, route.Transport, route.Source)
		case "--format=json", "--format json":
			err = json.NewEncoder(output).Encode(route)
		default:
			err = fmt.Errorf("usage: route show [--format=json]")
		}
		if err != nil {
			fmt.Fprintln(errorOutput, err)
			return 1
		}
		return 0
	}
	p := Policy{Account: c.Desktops[route.Desktop].Account}
	r := Request{Version: Protocol, Action: "read", Timeout: timeout}
	if len(args) == 2 && args[0] == "session" {
		r.Action = args[1]
	} else {
		r.Args = args
	}
	if writeCommand(r.Args) {
		r.Action = "write"
		if err := readWriteInput(&r, input, p); err != nil {
			fmt.Fprintln(errorOutput, err)
			return 1
		}
	}
	argv, err := p.Validate(r)
	if err != nil {
		fmt.Fprintln(errorOutput, err)
		return 1
	}
	// Carry the expected account across SSH; the desktop independently validates it.
	if r.Action == "read" || r.Action == "write" {
		r.Args = argv
		if _, err := p.Validate(r); err != nil {
			fmt.Fprintln(errorOutput, err)
			return 1
		}
		fmt.Fprintf(errorOutput, "Approval desktop: %s (running on %s; %s). Approve there if 1Password requests authorization.\n", route.Desktop, route.Machine, route.Transport)
	} else if r.Action == "stop" {
		fmt.Fprintf(errorOutput, "Stopping the shared secrets session on %s affects all tasks using it.\n", route.Desktop)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	result := send(ctx, c, route, r)
	if result.Version != Protocol {
		fmt.Fprintf(errorOutput, "Desktop %s: protocol mismatch; update both hosts\n", route.Desktop)
		return 1
	}
	if result.Error != "" {
		fmt.Fprintf(errorOutput, "Desktop %s: %s\n", route.Desktop, result.Error)
	} else if result.Exit != 0 {
		fmt.Fprintf(errorOutput, "Desktop %s: secrets request failed\n", route.Desktop)
	}
	if _, err := output.Write(result.Stdout); err != nil {
		return 1
	}
	if _, err := errorOutput.Write(result.Stderr); err != nil {
		return 1
	}
	return result.Exit
}

func dispatch(ctx context.Context, c Config, route Route, r Request) Response {
	if route.Transport == "ssh" {
		return external(ctx, r, "/usr/bin/ssh", sshRouteArgs(c.Desktops[route.Desktop]), "SSH route or desktop bridge failed; check the existing SSH connection and run op-bridge --desktop "+route.Desktop+" session doctor")
	}
	u, err := owner(c)
	if err != nil {
		return failure(err.Error())
	}
	if strconv.Itoa(os.Geteuid()) == u.Uid {
		return bridge(ctx, c, u, r)
	}
	caller, err := user.Current()
	if err != nil || caller.Username != c.Local.Caller {
		return failure("caller is not configured")
	}
	return external(ctx, r, "/usr/bin/sudo", []string{"-n", "-u", c.Local.Owner, InstalledBinary, "_bridge"}, "desktop launch permission is missing or the bridge failed")
}

// Only validated administrator configuration enters the fixed remote command.
// Request data is sent separately over stdin. The login shell sees no secrets.
func sshRouteArgs(d Desktop) []string {
	return []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes", "--", d.SSHHost, "/usr/bin/sudo -n -u '" + d.Owner + "' " + InstalledBinary + " _bridge"}
}
