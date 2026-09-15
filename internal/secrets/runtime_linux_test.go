package secrets

import (
	"fmt"
	"strings"
	"testing"
)

func TestPersistentTTYAndStreams(t *testing.T) {
	w := testWorker(t, `awk '{print $6, $7}' /proc/$$/stat
printf 'native diagnostic' >&2
exit 7
`)
	a, b := workerCall(t, w, readRequest()), workerCall(t, w, readRequest())
	if a.Exit != 7 || b.Exit != 7 || string(a.Stderr) != "native diagnostic" || string(a.Stdout) != string(b.Stdout) {
		t.Fatalf("status, stream, or terminal continuity failed: %+v %+v", a, b)
	}
	fields := strings.Fields(string(a.Stdout))
	if len(fields) != 2 || fields[1] == "0" || fields[0] != fmt.Sprint(w.cmd.Process.Pid) {
		t.Fatalf("no persistent controlling terminal: %q", a.Stdout)
	}
}
