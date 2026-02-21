package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func testPolicy(t *testing.T, extra string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte("version: 1\npresets: [mcp]\n" + extra))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeServer records what it receives and answers each request.
type fakeServer struct {
	received []string
	in       *io.PipeWriter
	out      *io.PipeReader
	done     chan struct{}
}

func startServer(t *testing.T, respond func(line string) string) *fakeServer {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &fakeServer{in: inW, out: outR, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer outW.Close()
		buf := make([]byte, 0, 1<<16)
		chunk := make([]byte, 4096)
		for {
			n, err := inR.Read(chunk)
			buf = append(buf, chunk[:n]...)
			for {
				i := bytes.IndexByte(buf, '\n')
				if i < 0 {
					break
				}
				line := string(buf[:i])
				buf = buf[i+1:]
				s.received = append(s.received, line)
				if reply := respond(line); reply != "" {
					if _, err := io.WriteString(outW, reply+"\n"); err != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return s
}

func noReply(string) string { return "" }

func run(t *testing.T, p *Proxy, s *fakeServer, input string) []string {
	t.Helper()
	var out bytes.Buffer
	if err := p.Run(strings.NewReader(input), &out, s.in, s.out); err != nil {
		t.Fatal(err)
	}
	<-s.done
	text := strings.TrimSpace(out.String())
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func toolError(t *testing.T, line string) string {
	t.Helper()
	var msg struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		t.Fatalf("bad line %q: %v", line, err)
	}
	if !msg.Result.IsError || len(msg.Result.Content) != 1 {
		t.Fatalf("not a tool error: %s", line)
	}
	return msg.Result.Content[0].Text
}

func TestAllowedCallReachesServer(t *testing.T) {
	s := startServer(t, func(string) string { return `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` })
	var seen []Verdict
	p := &Proxy{Policy: testPolicy(t, ""), Server: "crm", Observe: func(v Verdict) { seen = append(seen, v) }}
	got := run(t, p, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}`+"\n")
	if len(got) != 1 || !strings.Contains(got[0], `"ok":true`) {
		t.Fatalf("client got %q", got)
	}
	if len(s.received) != 1 {
		t.Fatalf("server got %q", s.received)
	}
	if len(seen) != 1 || seen[0].Tool != "mcp__crm__search" || seen[0].Report.Decision != policy.Allow {
		t.Errorf("seen = %+v", seen)
	}
}

func TestDeniedCallNeverReachesServer(t *testing.T) {
	s := startServer(t, noReply)
	p := &Proxy{Policy: testPolicy(t, "")}
	got := run(t, p, s, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_record","arguments":{"id":1}}}`+"\n")
	if len(s.received) != 0 {
		t.Fatalf("server received %q", s.received)
	}
	if len(got) != 1 {
		t.Fatalf("client got %q", got)
	}
	if text := toolError(t, got[0]); !strings.Contains(text, "destroys something") {
		t.Errorf("text = %q", text)
	}
	if !strings.Contains(got[0], `"id":7`) {
		t.Errorf("reply lost the id: %s", got[0])
	}
}

func TestConfirmIsRefusedWithoutAPlan(t *testing.T) {
	s := startServer(t, noReply)
	p := &Proxy{Policy: testPolicy(t, "settings: {unknown_tools: confirm}\n")}
	got := run(t, p, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"update_x"}}`+"\n")
	if len(s.received) != 0 || len(got) != 1 {
		t.Fatalf("received=%q got=%q", s.received, got)
	}
	if text := toolError(t, got[0]); !strings.Contains(text, "confirm") {
		t.Errorf("text = %q", text)
	}
}

func TestPlanMode(t *testing.T) {
	s := startServer(t, noReply)
	var queued []string
	p := &Proxy{
		Policy: testPolicy(t, "settings: {unknown_tools: confirm, confirm_mode: plan}\n"),
		Queue: func(v Verdict) (string, error) {
			queued = append(queued, v.Tool)
			if v.Tool == "bad" {
				return "", errors.New("disk full")
			}
			return "queued", nil
		},
	}
	got := run(t, p, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"update_x"}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bad"}}
`)
	if len(queued) != 2 || len(got) != 2 {
		t.Fatalf("queued=%q got=%q", queued, got)
	}
	if toolError(t, got[0]) != "queued" {
		t.Errorf("first = %s", got[0])
	}
	if text := toolError(t, got[1]); !strings.Contains(text, "disk full") {
		t.Errorf("second = %s", got[1])
	}
}

func TestMalformedMessagesStopAtTheProxy(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		want  string
		code  string
		seeID string
	}{
		{"not json", `{nope`, "parse", "-32700", ""},
		{"trailing data", `{"method":"tools/call"} {"x":1}`, "parse", "-32700", ""},
		{"number", `12`, "parse", "-32700", ""},
		{"no params", `{"id":1,"method":"tools/call"}`, "needs params", "-32600", `"id":1`},
		{"params array", `{"id":2,"method":"tools/call","params":[]}`, "needs params", "-32600", `"id":2`},
		{"no name", `{"id":3,"method":"tools/call","params":{}}`, "tool name", "-32600", `"id":3`},
		{"numeric name", `{"id":4,"method":"tools/call","params":{"name":1}}`, "tool name", "-32600", `"id":4`},
		{"bad arguments", `{"id":5,"method":"tools/call","params":{"name":"a","arguments":[1]}}`, "arguments", "-32600", `"id":5`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := startServer(t, noReply)
			p := &Proxy{Policy: testPolicy(t, "")}
			got := run(t, p, s, tt.line+"\n")
			if len(s.received) != 0 {
				t.Fatalf("server received %q", s.received)
			}
			if len(got) != 1 || !strings.Contains(got[0], tt.want) || !strings.Contains(got[0], tt.code) || !strings.Contains(got[0], tt.seeID) {
				t.Errorf("client got %q", got)
			}
		})
	}
}

func TestOtherMessagesPassThrough(t *testing.T) {
	s := startServer(t, noReply)
	p := &Proxy{Policy: testPolicy(t, "")}
	run(t, p, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}

{"jsonrpc":"2.0","method":"notifications/initialized"}
`)
	if len(s.received) != 2 {
		t.Errorf("received %q", s.received)
	}
}

func TestBatch(t *testing.T) {
	s := startServer(t, noReply)
	p := &Proxy{Policy: testPolicy(t, "")}
	got := run(t, p, s, `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_x"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_x"}},5]`+"\n")
	if len(s.received) != 1 || strings.Contains(s.received[0], "delete_x") || !strings.Contains(s.received[0], "read_x") {
		t.Fatalf("received %q", s.received)
	}
	if len(got) != 2 {
		t.Fatalf("client got %q", got)
	}

	s = startServer(t, noReply)
	p = &Proxy{Policy: testPolicy(t, "")}
	got = run(t, p, s, `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_x"}}]`+"\n")
	if len(s.received) != 0 || len(got) != 1 {
		t.Fatalf("received=%q got=%q", s.received, got)
	}

	s = startServer(t, noReply)
	p = &Proxy{Policy: testPolicy(t, "")}
	got = run(t, p, s, "[1,\n")
	if len(s.received) != 0 || len(got) != 1 || !strings.Contains(got[0], "-32700") {
		t.Fatalf("received=%q got=%q", s.received, got)
	}
}

func TestToolsListFiltering(t *testing.T) {
	list := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search"},{"name":"delete_record"},{"name":"mcp_drop_table"},"odd"]}}`
	respond := func(string) string { return list }

	s := startServer(t, respond)
	p := &Proxy{Policy: testPolicy(t, ""), HideDenied: true}
	got := run(t, p, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if len(got) != 1 {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(got[0], "delete_record") || strings.Contains(got[0], "drop_table") {
		t.Errorf("denied tools were listed: %s", got[0])
	}
	if !strings.Contains(got[0], "search") || !strings.Contains(got[0], "odd") {
		t.Errorf("allowed tools were lost: %s", got[0])
	}

	s = startServer(t, respond)
	p = &Proxy{Policy: testPolicy(t, "")}
	got = run(t, p, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if len(got) != 1 || !strings.Contains(got[0], "delete_record") {
		t.Errorf("got %q", got)
	}
}

func TestServerLinesPassWhenNotAList(t *testing.T) {
	lines := []string{
		`{"jsonrpc":"2.0","method":"notifications/message"}`,
		`{"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"delete_x"}]}}`,
		`not json`,
	}
	p := &Proxy{HideDenied: true, Policy: testPolicy(t, ""), listIDs: map[string]bool{"json.Number:1": true}}
	for _, line := range lines {
		if got := p.fromServer([]byte(line)); string(got) != line {
			t.Errorf("changed %q to %q", line, got)
		}
	}
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"error":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"tools":5}}`,
	} {
		p.listIDs = map[string]bool{"json.Number:1": true}
		if got := p.fromServer([]byte(line)); string(got) != line {
			t.Errorf("changed %q to %q", line, got)
		}
	}
}

func TestConcurrentRepliesDoNotInterleave(t *testing.T) {
	var mu sync.Mutex
	count := 0
	s := startServer(t, func(string) string {
		mu.Lock()
		defer mu.Unlock()
		count++
		return `{"jsonrpc":"2.0","id":100,"result":{}}`
	})
	var input strings.Builder
	for range 50 {
		input.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_x"}}` + "\n")
		input.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_x"}}` + "\n")
	}
	p := &Proxy{Policy: testPolicy(t, "")}
	got := run(t, p, s, input.String())
	if len(got) != 100 {
		t.Fatalf("lines = %d", len(got))
	}
	for _, line := range got {
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("interleaved line %q", line)
		}
	}
}
