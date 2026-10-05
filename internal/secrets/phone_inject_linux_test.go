package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func injectFixtureRequest(input string) Request {
	return Request{Version: Protocol, Action: "read", Args: []string{"inject", "--account=" + testPolicy.Account}, Stdin: []byte(input), Timeout: 2}
}
func TestPhoneInjectCallerBatchAckAndPrivacy(t *testing.T) {
	s := newPhoneSession("fixture", "caller", testPolicy.Account)
	var history []historyEvent
	s.history = func(event historyEvent) error { history = append(history, event); return nil }
	c, done := fixtureCaller(t, s)
	result := make(chan Response, 1)
	go func() {
		result <- exchangePhone(c, injectFixtureRequest("PRIVATE_TEMPLATE{{op://PRIVATE_VAULT/PRIVATE_ITEM/f}}/{{op://PRIVATE_VAULT/PRIVATE_ITEM/f}}/{{op://v/i/g}}"))
	}()
	p := waitPending(t, s)
	if p.Kind != "inject" || p.UniqueCount != 2 || p.OccurrenceCount != 3 {
		t.Fatal("incorrect batch metadata")
	}
	if code := s.decide(p.ID, "release", "PARTIAL_PRIVATE_VALUE"); code != "invalid_request" {
		t.Fatal("single release approved batch")
	}
	tmpl := s.entries[p.ID].request.Template
	if code := s.decideBatch(p.ID, "release_batch", "", batchValues(tmpl, "PRIVATE_VALUE")); code != "invalid_batch" {
		t.Fatal("partial release accepted")
	}
	if s.snapshot(p.ID)[0].State != "pending" {
		t.Fatal("partial release consumed request")
	}
	if code := s.decideBatch(p.ID, "release_batch", "", batchValues(tmpl, "PRIVATE_VALUE", "")); code != "" {
		t.Fatal("complete release rejected")
	}
	r := <-result
	<-done
	if r.Error != "" || !bytes.Equal(r.Stdout, []byte("PRIVATE_TEMPLATEPRIVATE_VALUE/PRIVATE_VALUE/")) {
		t.Fatal("batch output incorrect")
	}
	clear(r.Stdout)
	if s.snapshot(p.ID)[0].State != "completed" {
		t.Fatal("receipt not acknowledged")
	}
	encoded, _ := json.Marshal(history)
	for _, marker := range []string{"PRIVATE_TEMPLATE", "PRIVATE_VAULT", "PRIVATE_ITEM", "PRIVATE_VALUE"} {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatal("private batch data persisted in history")
		}
	}
	if tmpl.input != nil || tmpl.parts != nil {
		t.Fatal("terminal template retained")
	}
	if code := s.decideBatch(p.ID, "release_batch", "", nil); code != "request_not_pending" {
		t.Fatal("duplicate release accepted")
	}
}
func TestPhoneInjectNoReferenceAndUnsupportedTemplates(t *testing.T) {
	for _, input := range []string{"", "literal\r\n$5 {}", "{{op://v/i/f}} {{op://v//f}}"} {
		s := newPhoneSession("fixture", "caller", testPolicy.Account)
		c, done := fixtureCaller(t, s)
		r := exchangePhone(c, injectFixtureRequest(input))
		<-done
		if strings.Contains(input, "op://") {
			if r.ErrorCode != "unsupported_template" || len(r.Stdout) != 0 {
				t.Fatal("unsupported input returned output")
			}
		} else if !bytes.Equal(r.Stdout, []byte(input)) || r.Error != "" {
			t.Fatal("literal template changed")
		}
		if len(s.snapshot("")) != 0 {
			t.Fatal("unnecessary approval created")
		}
	}
}
func TestPhoneInjectConcurrentReleaseAndDeny(t *testing.T) {
	for _, other := range []string{"release_batch", "deny"} {
		s := newPhoneSession("fixture", "caller", testPolicy.Account)
		c, done := fixtureCaller(t, s)
		results := make(chan Response, 1)
		go func() { results <- exchangePhone(c, injectFixtureRequest("{{op://v/i/f}}")) }()
		p := waitPending(t, s)
		tmpl := s.entries[p.ID].request.Template
		values := batchValues(tmpl, "FIXTURE_VALUE")
		var wg sync.WaitGroup
		codes := make(chan string, 2)
		for _, method := range []string{"release_batch", other} {
			wg.Add(1)
			go func(method string) { defer wg.Done(); codes <- s.decideBatch(p.ID, method, "", values) }(method)
		}
		wg.Wait()
		close(codes)
		accepted := 0
		for code := range codes {
			if code == "" {
				accepted++
			} else if code != "request_not_pending" {
				t.Fatal("unexpected decision error")
			}
		}
		r := <-results
		<-done
		if accepted != 1 {
			t.Fatal("batch not consumed atomically")
		}
		if r.Error != "" && len(r.Stdout) != 0 {
			t.Fatal("failed decision returned output")
		}
		clear(r.Stdout)
		if s.pending != 0 {
			t.Fatal("queue count incorrect")
		}
	}
}
func TestPhoneInjectExpiryCancellationAndLostReceipt(t *testing.T) {
	for _, action := range []string{"expire", "cancel", "deny", "lost_ack", "wrong_ack"} {
		s := newPhoneSession("fixture", "caller", testPolicy.Account)
		c, done := fixtureCaller(t, s)
		r := injectFixtureRequest("{{op://v/i/a}}{{op://v/i/b}}")
		r.Timeout = 1
		if json.NewEncoder(c).Encode(r) != nil {
			t.Fatal("fixture send failed")
		}
		p := waitPending(t, s)
		switch action {
		case "cancel":
			c.Close()
		case "deny":
			s.decide(p.ID, "deny", "")
			var result Response
			json.NewDecoder(c).Decode(&result)
			if len(result.Stdout) != 0 {
				t.Fatal("denial returned output")
			}
		case "lost_ack", "wrong_ack":
			s.decideBatch(p.ID, "release_batch", "", batchValues(s.entries[p.ID].request.Template, "FIXTURE_A", "FIXTURE_B"))
			var result Response
			if json.NewDecoder(c).Decode(&result) != nil {
				t.Fatal("fixture receive failed")
			}
			clear(result.Stdout)
			if action == "wrong_ack" {
				json.NewEncoder(c).Encode(map[string]string{"ack": "wrong"})
			} else {
				c.Close()
			}
		}
		<-done
		want := map[string]string{"expire": "expired", "cancel": "cancelled", "deny": "denied", "lost_ack": "delivery_uncertain", "wrong_ack": "delivery_uncertain"}[action]
		if s.snapshot(p.ID)[0].State != want {
			t.Fatal("incorrect terminal batch state")
		}
		if code := s.decideBatch(p.ID, "release_batch", "", nil); code != "request_not_pending" {
			t.Fatal("terminal batch released again")
		}
	}
}
func TestPhoneInjectOutputLimitReturnsNoStdout(t *testing.T) {
	s := newPhoneSession("fixture", "caller", testPolicy.Account)
	c, done := fixtureCaller(t, s)
	result := make(chan Response, 1)
	go func() { result <- exchangePhone(c, injectFixtureRequest(strings.Repeat("{{op://v/i/f}}", 256)+"x")) }()
	p := waitPending(t, s)
	if code := s.decideBatch(p.ID, "release_batch", "", batchValues(s.entries[p.ID].request.Template, strings.Repeat("x", phoneValueLimit))); code != "output_limit" {
		t.Fatal("oversized output accepted")
	}
	r := <-result
	<-done
	if len(r.Stdout) != 0 || r.ErrorCode != "output_limit" || s.snapshot(p.ID)[0].State != "failed" {
		t.Fatal("output limit did not fail entire batch")
	}
}
func TestPhoneInjectApprovalProtocolCapabilitiesAndPrivacy(t *testing.T) {
	s := newPhoneSession("fixture", "caller", testPolicy.Account)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tmpl, _ := parsePhoneTemplate([]byte("PRIVATE_TEMPLATE{{op://v/i/f}}{{op://v/i/f}}"))
	e, code := s.add(ctx, phoneSelection{Account: testPolicy.Account, Template: tmpl})
	if code != "" {
		t.Fatal("fixture add failed")
	}
	defer s.finish(e, "cancelled")
	server := httptest.NewServer(httpHandler(s))
	defer server.Close()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal("fixture connect failed")
	}
	defer c.CloseNow()
	for i, msg := range []approvalMessage{
		{Version: 1, ID: "old", Method: "list"},
		{Version: 1, ID: "new", Method: "list", Capabilities: []string{phoneBatchCapability}},
		{Version: 1, ID: "get", Method: "get", RequestID: e.request.ID},
		{Version: 1, ID: "partial", Method: "release_batch", RequestID: e.request.ID, Values: []phoneBatchValue{}},
		{Version: 1, ID: "release", Method: "release_batch", RequestID: e.request.ID, Values: batchValues(tmpl, "PRIVATE_VALUE")},
	} {
		// Empty values array must remain present for the partial fixture.
		data, _ := json.Marshal(msg)
		if i == 3 {
			data = []byte(`{"version":1,"id":"partial","method":"release_batch","request_id":"` + e.request.ID + `","values":[]}`)
		}
		if c.Write(ctx, websocket.MessageText, data) != nil {
			t.Fatal("fixture write failed")
		}
		_, reply, err := c.Read(ctx)
		if err != nil {
			t.Fatal("fixture read failed")
		}
		if bytes.Contains(reply, []byte("PRIVATE_VALUE")) || bytes.Contains(reply, []byte("PRIVATE_TEMPLATE")) {
			t.Fatal("secret/template leaked in approval reply")
		}
		var decoded approvalReply
		if json.Unmarshal(reply, &decoded) != nil {
			t.Fatal("invalid reply")
		}
		if !hasPhoneBatchCapability(decoded.Capabilities) {
			t.Fatal("missing capability")
		}
		if i == 0 && len(decoded.Requests) != 0 {
			t.Fatal("old client saw batch")
		}
		if i == 1 && (len(decoded.Requests) != 1 || decoded.Requests[0].Fields != nil) {
			t.Fatal("list did not contain summary")
		}
		if i == 2 && len(decoded.Requests[0].Fields) != 1 {
			t.Fatal("get omitted fields")
		}
		if i == 3 && decoded.Error != "invalid_batch" {
			t.Fatal("partial batch not rejected")
		}
	}
}
func TestPhoneInjectStrictApprovalJSON(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"id":"x","method":"release_batch","request_id":"r","values":[{"id":"f1","value":"a","value":"b"}]}`,
		`{"version":1,"id":"x","method":"release_batch","method":"deny","request_id":"r","values":[]}`,
		`{"version":1,"id":"x","method":"release_batch","request_id":"r","values":[{"id":"f1","value":"\ud800"}]}`,
		`{"version":1,"id":"x","method":"release_batch","request_id":"r","value":"a","values":[]}`,
		`{"version":1,"id":"x","method":"deny","request_id":"r","values":[]}`,
		`{"version":1,"id":"x","method":"release_batch","request_id":"r","values":[],"template":"bad"}`,
		`{"version":1,"id":"x","method":"release_batch","request_id":"r","values":[]} {}`,
	} {
		var msg approvalMessage
		if decodeApprovalMessage([]byte(raw), &msg) == nil {
			t.Fatal("ambiguous/malformed approval accepted")
		}
	}
	var msg approvalMessage
	if decodeApprovalMessage([]byte(`{"version":1,"id":"x","method":"release_batch","request_id":"r","values":[{"id":"f1","value":"\ud83d\ude00"}]}`), &msg) != nil {
		t.Fatal("valid surrogate pair rejected")
	}
}
func TestPhoneInjectRoutingPinnedInputAndFailure(t *testing.T) {
	c := routingConfig(t, "builder")
	c.Desktops["phone"] = Desktop{Transport: "remote-codex", Owner: "alice", Account: testPolicy.Account}
	c.DefaultDesktop = "phone"
	var out, stderr bytes.Buffer
	calls := 0
	code := runClient(c, []string{"inject"}, strings.NewReader("{{op://v/i/f}}"), &out, &stderr, func(ctx context.Context, _ Config, route Route, r Request) Response {
		calls++
		if route.Transport != "remote-codex" || r.Action != "read" || string(r.Stdin) != "{{op://v/i/f}}" || len(r.Args) != 2 || r.Args[1] != "--account="+testPolicy.Account {
			t.Fatal("incorrect phone caller contract")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing shared timeout")
		}
		return Response{Version: Protocol, Exit: 1, Error: "fixed_error", Stdout: []byte("PARTIAL_PRIVATE")}
	})
	if code == 0 || out.Len() != 0 || calls != 1 {
		t.Fatal("phone inject failure exposed partial output")
	}
	out.Reset()
	stderr.Reset()
	calls = 0
	code = runClient(c, []string{"inject"}, strings.NewReader("{{op://v/i/f}} {{bad}}"), &out, &stderr, func(context.Context, Config, Route, Request) Response { calls++; return Response{Version: Protocol} })
	if code == 0 || calls != 0 || out.Len() != 0 {
		t.Fatal("unsupported template dispatched")
	}
	for _, args := range [][]string{{"inject", "--in-file", "x"}, {"inject", "--account=other"}, {"inject", "--format=json"}} {
		if runClient(c, args, strings.NewReader(""), &out, &stderr, func(context.Context, Config, Route, Request) Response {
			t.Fatal("invalid options dispatched")
			return Response{}
		}) == 0 {
			t.Fatal("invalid options accepted")
		}
	}
}
func TestPhoneInjectExchangeRejectsOversizeAndFailedAck(t *testing.T) {
	// net.Pipe is a disposable caller transport, not the live phone service.
	for _, action := range []string{"large", "failed_ack"} {
		caller, backend := net.Pipe()
		defer caller.Close()
		go func() {
			defer backend.Close()
			var req Request
			json.NewDecoder(backend).Decode(&req)
			output := []byte("FIXTURE_VALUE")
			if action == "large" {
				output = bytes.Repeat([]byte("x"), MaxOutput+1)
			}
			json.NewEncoder(backend).Encode(Response{Version: Protocol, Stdout: output, RequestID: "fixture"})
		}()
		r := exchangePhone(caller, injectFixtureRequest("{{op://v/i/f}}"))
		if r.Error == "" || len(r.Stdout) != 0 {
			t.Fatal("oversize/failed acknowledgment exposed output")
		}
	}
}

func TestPhoneInjectOversizeApprovalDoesNotConsumeBatch(t *testing.T) {
	s := newPhoneSession("fixture", "caller", testPolicy.Account)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tmpl, _ := parsePhoneTemplate([]byte("{{op://v/i/a}}{{op://v/i/b}}"))
	entry, code := s.add(ctx, phoneSelection{Account: testPolicy.Account, Template: tmpl})
	if code != "" {
		t.Fatal("fixture add failed")
	}
	defer s.finish(entry, "cancelled")
	server := httptest.NewServer(httpHandler(s))
	defer server.Close()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal("fixture connect failed")
	}
	defer c.CloseNow()
	msg := approvalMessage{Version: 1, ID: "large", Method: "release_batch", RequestID: entry.request.ID, Values: batchValues(tmpl, strings.Repeat("\x01", phoneValueLimit), strings.Repeat("\x01", phoneValueLimit))}
	encoded, _ := json.Marshal(msg)
	if len(encoded) <= phoneWireLimit {
		t.Fatal("fixture not over transport bound")
	}
	c.Write(ctx, websocket.MessageText, encoded)
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("oversized approval accepted")
	}
	if s.snapshot(entry.request.ID)[0].State != "pending" {
		t.Fatal("oversized payload consumed batch")
	}
	select {
	case <-entry.result:
		t.Fatal("oversized payload staged values")
	default:
	}
}
func TestPhoneInjectEarlyReceiptDoesNotCompleteRequest(t *testing.T) {
	s := newPhoneSession("fixture", "caller", testPolicy.Account)
	c, done := fixtureCaller(t, s)
	json.NewEncoder(c).Encode(injectFixtureRequest("{{op://v/i/f}}"))
	p := waitPending(t, s)
	json.NewEncoder(c).Encode(map[string]string{"ack": p.ID})
	<-done
	if s.snapshot(p.ID)[0].State != "cancelled" {
		t.Fatal("early acknowledgment confirmed delivery")
	}
}
func TestPhoneInjectLargeCompleteBatchCanBeReceived(t *testing.T) {
	s := newPhoneSession("fixture", "caller", testPolicy.Account)
	c, done := fixtureCaller(t, s)
	result := make(chan Response, 1)
	go func() { result <- exchangePhone(c, injectFixtureRequest("{{op://v/i/a}}{{op://v/i/a}}{{op://v/i/b}}")) }()
	p := waitPending(t, s)
	if code := s.decideBatch(p.ID, "release_batch", "", batchValues(s.entries[p.ID].request.Template, strings.Repeat("a", phoneValueLimit), strings.Repeat("b", phoneValueLimit))); code != "" {
		t.Fatal("large valid batch rejected")
	}
	r := <-result
	<-done
	if r.Error != "" || len(r.Stdout) != 3*phoneValueLimit || s.snapshot(p.ID)[0].State != "completed" {
		t.Fatal("old single-value reader limit still applies")
	}
	clear(r.Stdout)
}
