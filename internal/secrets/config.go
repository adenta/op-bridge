package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// Config belongs to one machine. A desktop can also route outgoing requests to
// another desktop; local bridge capability is independent of its default route.
type Config struct {
	Version        int                `json:"version"`
	Machine        string             `json:"machine"`
	Local          *LocalBridge       `json:"local_bridge,omitempty"`
	DefaultDesktop string             `json:"default_desktop"`
	Desktops       map[string]Desktop `json:"desktops"`
}

type LocalBridge struct {
	Owner   string `json:"owner"`
	Caller  string `json:"caller,omitempty"`
	Account string `json:"account"`
}

type Desktop struct {
	Transport string `json:"transport"`
	SSHHost   string `json:"ssh_host,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Account   string `json:"account"`
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var accountPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

func validAccount(account string) bool {
	return len(account) <= 253 && accountPattern.MatchString(account)
}
func validUser(user string) bool { return user != "root" && userPattern.MatchString(user) }

func validateConfig(c Config) error {
	if c.Version != ConfigVersion {
		return fmt.Errorf("configuration version mismatch; use op-bridge configuration version %d", ConfigVersion)
	}
	if !namePattern.MatchString(c.Machine) {
		return fmt.Errorf("invalid execution host identifier")
	}
	if c.Local != nil {
		if !validUser(c.Local.Owner) || (c.Local.Caller != "" && (!validUser(c.Local.Caller) || c.Local.Owner == c.Local.Caller)) {
			return fmt.Errorf("local bridge requires a non-root owner and, if supplied, a distinct non-root caller")
		}
		if !validAccount(c.Local.Account) {
			return fmt.Errorf("local bridge requires an account sign-in address")
		}
	}
	if len(c.Desktops) == 0 || len(c.Desktops) > 64 {
		return fmt.Errorf("configure between 1 and 64 desktops")
	}
	localCount := 0
	for name, d := range c.Desktops {
		if !namePattern.MatchString(name) || !validAccount(d.Account) {
			return fmt.Errorf("invalid desktop identifier or account sign-in address")
		}
		switch d.Transport {
		case "local":
			localCount++
			if c.Local == nil || d.Account != c.Local.Account || d.SSHHost != "" || d.Owner != "" {
				return fmt.Errorf("local route must match the local bridge account and omit SSH fields")
			}
		case "ssh":
			if !namePattern.MatchString(d.SSHHost) || !validUser(d.Owner) {
				return fmt.Errorf("SSH routes require a safe SSH alias and non-root desktop owner")
			}
		default:
			return fmt.Errorf("desktop transport must be local or ssh")
		}
	}
	if localCount > 1 {
		return fmt.Errorf("configure at most one local desktop route")
	}
	if _, ok := c.Desktops[c.DefaultDesktop]; !ok {
		return fmt.Errorf("default desktop is not configured")
	}
	return nil
}

func decodeConfig(r io.Reader) (Config, error) {
	var c Config
	data, err := io.ReadAll(io.LimitReader(r, MaxRequest+1))
	if err != nil || len(data) > MaxRequest {
		return c, fmt.Errorf("configuration exceeds limit or could not be read")
	}
	// Decode through the strict helper; trailing JSON must not be ignored.
	err = decodeConfigJSON(data, &c)
	if err != nil {
		return c, fmt.Errorf("invalid configuration JSON")
	}
	return c, validateConfig(c)
}

// Check duplicate keys before the typed decode, including nested destinations.
// encoding/json normally accepts duplicates, which makes policy review ambiguous.
func uniqueJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid key")
			}
			seen[name] = true
			if err := uniqueJSON(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid delimiter")
	}
	_, err = d.Token()
	return err
}

func decodeConfigJSON(data []byte, c *Config) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueJSON(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(c)
}
