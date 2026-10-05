package secrets

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

const historyWarning = "op-bridge: access history could not be written or maintained; history may be incomplete\n"

// This deliberately contains only allowlisted metadata, never native output.
type historyEvent struct {
	Time      time.Time `json:"time"`
	ID        string    `json:"request_id"`
	Event     string    `json:"event"`
	Operation string    `json:"operation"`
	DryRun    bool      `json:"dry_run"`
	Vault     string    `json:"vault,omitempty"`
	Item      string    `json:"item,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Exit      *int      `json:"exit,omitempty"`
}

func (p Policy) requestHistory(r Request, id string) historyEvent {
	e := historyEvent{ID: id, Event: "request"}
	args, err := p.Validate(r)
	if err != nil || (r.Action != "read" && r.Action != "write") {
		return e
	}
	n := 2
	if args[0] == "read" || args[0] == "inject" {
		n = 1
	}
	e.Operation = strings.Join(args[:n], " ")
	var item string
	for _, arg := range args[n:] {
		if value, ok := strings.CutPrefix(arg, "--vault="); ok {
			e.Vault = historyIdentifier(value)
		} else if arg == "--dry-run" {
			e.DryRun = true
		} else if !strings.HasPrefix(arg, "-") {
			item = arg
		}
	}
	if args[0] == "read" {
		parts := strings.SplitN(strings.TrimPrefix(item, "op://"), "/", 3)
		e.Vault, e.Item = historyIdentifier(parts[0]), historyIdentifier(parts[1])
	} else {
		e.Item = historyIdentifier(item)
	}
	return e
}

func historyIdentifier(s string) string {
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

type accessHistory struct {
	mu  sync.Mutex
	dir string
	now func() time.Time
	day string
}

// Open each path component without following symlinks. Existing parent
// directories may be shared-readable, but must belong to this user and not
// permit writes from others. History directories themselves are private.
func historyDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("invalid history directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i, part := range parts {
		private := i >= len(parts)-2
		err = unix.Mkdirat(fd, part, 0700)
		if err != nil && err != unix.EEXIST {
			unix.Close(fd)
			return -1, err
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			unix.Close(fd)
			return -1, e
		}
		// Root-owned ancestors (/home, for example) are acceptable.
		trustedStickyParent := !private && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if (st.Uid != uint32(os.Geteuid()) && (st.Uid != 0 || private)) || (st.Mode&0022 != 0 && !trustedStickyParent) || (private && st.Mode&0777 != 0700) {
			unix.Close(fd)
			return -1, fmt.Errorf("unsafe history directory")
		}
	}
	return fd, nil
}

func (h *accessHistory) append(e historyEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now().UTC()
	fd, err := historyDirectory(h.dir)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), h.dir)
	defer dir.Close()
	day := now.Format("2006-01-02")
	if h.day != day {
		entries, err := dir.ReadDir(-1)
		if err != nil {
			return err
		}
		cutoff := now.Truncate(24*time.Hour).AddDate(0, 0, -90)
		for _, entry := range entries {
			date, err := time.Parse("2006-01-02.jsonl", entry.Name())
			if err == nil && date.Before(cutoff) && entry.Type().IsRegular() {
				if err := unix.Unlinkat(fd, entry.Name(), 0); err != nil {
					return err
				}
			}
		}
		h.day = day
	}
	if e.Event == "" {
		return nil
	} // startup maintenance
	logFD, err := unix.Openat(fd, day+".jsonl", unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(logFD), day+".jsonl")
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(logFD, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return fmt.Errorf("unsafe history file")
	}
	e.Time = now
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return dir.Sync()
}
