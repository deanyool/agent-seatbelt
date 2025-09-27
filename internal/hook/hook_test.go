package hook

import (
	"bytes"
	"strings"
	"testing"

	"github.com/deanyool/agent-seatbelt/internal/policy"
)

func TestDeny(t *testing.T) {
	p, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	in := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`
	if code := Run(strings.NewReader(in), &out, &errOut, p); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Errorf("out = %q", out.String())
	}
}

func TestBadPayloadBlocks(t *testing.T) {
	p, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(strings.NewReader("nope"), &out, &errOut, p); code != 2 {
		t.Fatalf("code = %d", code)
	}
}
