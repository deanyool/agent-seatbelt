// Package mcp sits between an MCP client and a stdio MCP server, checking each tool
// call against the policy before the server sees it.
//
// The stdio transport carries one JSON-RPC message per line. Client messages are
// decoded and re-encoded rather than copied, so the server receives exactly what
// was checked. JSON that two parsers would read differently, such as a duplicated
// "name" key, can't reach it.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

// JSON-RPC error codes.
const (
	codeParse   = -32700
	codeInvalid = -32600
)

// Verdict is one evaluated tool call, handed to the caller for logging.
type Verdict struct {
	Tool   string
	Input  map[string]any
	Report policy.Report
}

// Proxy forwards traffic between a client and a server.
type Proxy struct {
	Policy *policy.Policy
	// Server is the label used in rule matching, as in mcp__<server>__<tool>.
	Server string
	// HideDenied removes denied tools from tools/list, so agents don't plan around
	// tools they can't use.
	HideDenied bool
	// Observe is called with each tool call verdict, for the audit log.
	Observe func(Verdict)
	// Queue handles a confirm decision when the policy says to plan. It returns the
	// message for the model.
	Queue func(Verdict) (string, error)

	mu      sync.Mutex // guards writes to the client and listIDs
	listIDs map[string]bool
}

// Run moves messages until the client hangs up or the server stops.
func (p *Proxy) Run(clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser, serverOut io.Reader) error {
	p.listIDs = map[string]bool{}
	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = p.pumpServer(serverOut, clientOut)
	}()
	clientErr := p.pumpClient(clientIn, clientOut, serverIn)
	closeErr := serverIn.Close()
	wg.Wait()
	return errors.Join(clientErr, serverErr, closeErr)
}

func (p *Proxy) pumpClient(in io.Reader, clientOut, serverIn io.Writer) error {
	r := bufio.NewReader(in)
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if werr := p.fromClient(line, clientOut, serverIn); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (p *Proxy) pumpServer(in io.Reader, clientOut io.Writer) error {
	r := bufio.NewReader(in)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if werr := p.send(clientOut, p.fromServer(line)); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (p *Proxy) send(w io.Writer, line []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := w.Write(line)
	return err
}

// decode reads a JSON value keeping numbers exact, so re-encoding doesn't change
// large integers.
func decode(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

func (p *Proxy) fromClient(line []byte, clientOut, serverIn io.Writer) error {
	trimmed := bytes.TrimSpace(line)
	if trimmed[0] == '[' {
		return p.batch(trimmed, clientOut, serverIn)
	}
	var msg map[string]any
	if err := decode(trimmed, &msg); err != nil {
		return p.send(clientOut, errorLine(nil, codeParse, "seatbelt could not parse this message"))
	}
	reply, _ := p.inspect(msg)
	if reply != nil {
		return p.send(clientOut, reply)
	}
	_, err := serverIn.Write(line)
	return err
}

// batch handles a JSON-RPC array. Refused calls are answered here and the rest are
// forwarded as one batch.
func (p *Proxy) batch(data []byte, clientOut, serverIn io.Writer) error {
	var items []any
	if err := decode(data, &items); err != nil {
		return p.send(clientOut, errorLine(nil, codeParse, "seatbelt could not parse this batch"))
	}
	forward := make([]any, 0, len(items))
	for _, item := range items {
		msg, ok := item.(map[string]any)
		if !ok {
			if err := p.send(clientOut, errorLine(nil, codeInvalid, "batch item is not an object")); err != nil {
				return err
			}
			continue
		}
		reply, pass := p.inspect(msg)
		if reply != nil {
			if err := p.send(clientOut, reply); err != nil {
				return err
			}
			continue
		}
		forward = append(forward, pass)
	}
	if len(forward) == 0 {
		return nil
	}
	return writeJSON(serverIn, forward)
}

// inspect decides what happens to one client message. It returns either a reply
// for the client or the message to forward.
func (p *Proxy) inspect(msg map[string]any) (reply []byte, forward map[string]any) {
	method, _ := msg["method"].(string)
	switch method {
	case "tools/list":
		if p.HideDenied {
			if key, ok := idKey(msg["id"]); ok {
				p.mu.Lock()
				p.listIDs[key] = true
				p.mu.Unlock()
			}
		}
	case "tools/call":
		return p.toolCall(msg), msg
	}
	return nil, msg
}

func (p *Proxy) toolCall(msg map[string]any) []byte {
	id := msg["id"]
	params, ok := msg["params"].(map[string]any)
	if !ok {
		return errorLine(id, codeInvalid, "tools/call needs params")
	}
	name, ok := params["name"].(string)
	if !ok || name == "" {
		return errorLine(id, codeInvalid, "tools/call needs a tool name")
	}
	input, _ := params["arguments"].(map[string]any)
	if params["arguments"] != nil && input == nil {
		return errorLine(id, codeInvalid, "tools/call arguments must be an object")
	}
	rep := p.Policy.EvaluateTool(p.fullName(name), input)
	v := Verdict{Tool: p.fullName(name), Input: input, Report: rep}
	if p.Observe != nil {
		p.Observe(v)
	}
	switch rep.Decision {
	case policy.Allow:
		return nil
	case policy.Confirm:
		if p.Policy.Settings.ConfirmMode == policy.ConfirmPlan && p.Queue != nil {
			text, err := p.Queue(v)
			if err != nil {
				return refusal(id, "seatbelt: could not queue this call: "+err.Error())
			}
			return refusal(id, text)
		}
		return refusal(id, "seatbelt: this tool call needs a person to confirm it: "+rep.Reason())
	}
	return refusal(id, "seatbelt: "+rep.Reason())
}

func (p *Proxy) fullName(tool string) string {
	if p.Server == "" {
		return tool
	}
	return "mcp__" + p.Server + "__" + tool
}

// refusal is a successful JSON-RPC response carrying a tool error, which is how MCP
// reports failures the model should be able to read and react to.
func refusal(id any, text string) []byte {
	return encodeLine(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"isError": true,
			"content": []any{map[string]any{"type": "text", "text": text}},
		},
	})
}

func errorLine(id any, code int, text string) []byte {
	return encodeLine(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": text},
	})
}

func encodeLine(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"seatbelt encoding failure"}}` + "\n")
	}
	return append(data, '\n')
}

func writeJSON(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func idKey(id any) (string, bool) {
	if id == nil {
		return "", false
	}
	return fmt.Sprintf("%T:%v", id, id), true
}

// fromServer returns the line to pass to the client, filtering tools/list results
// that were asked for with HideDenied on. A line it can't make sense of is passed
// through unchanged: the proxy guards the server, not the client.
func (p *Proxy) fromServer(line []byte) []byte {
	if !p.HideDenied {
		return line
	}
	var msg map[string]any
	if err := decode(bytes.TrimSpace(line), &msg); err != nil {
		return line
	}
	key, ok := idKey(msg["id"])
	if !ok {
		return line
	}
	p.mu.Lock()
	wanted := p.listIDs[key]
	delete(p.listIDs, key)
	p.mu.Unlock()
	if !wanted {
		return line
	}
	result, ok := msg["result"].(map[string]any)
	if !ok {
		return line
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		return line
	}
	kept := make([]any, 0, len(tools))
	for _, t := range tools {
		if tool, ok := t.(map[string]any); ok {
			if name, ok := tool["name"].(string); ok {
				if p.Policy.EvaluateTool(p.fullName(name), nil).Decision == policy.Deny {
					continue
				}
			}
		}
		kept = append(kept, t)
	}
	result["tools"] = kept
	return encodeLine(msg)
}
