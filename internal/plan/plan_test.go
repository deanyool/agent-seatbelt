package plan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tmpPlan(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "dir", "plan.json")
}

func noCheck(Entry) error { return nil }

func TestLoadMissing(t *testing.T) {
	p, err := Load(tmpPlan(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 {
		t.Errorf("entries = %+v", p.Entries)
	}
}

func TestLoadBad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("want an error for bad JSON")
	}
	if err := os.WriteFile(path, []byte(`{"version": 7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("want a version error, got %v", err)
	}
}

func TestApproveThenApply(t *testing.T) {
	path := tmpPlan(t)
	a, err := Add(path, Entry{Command: "git push", CWD: "/w"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == "" || a.Status != Pending {
		t.Errorf("entry = %+v", a)
	}
	if _, err := Add(path, Entry{Command: "kubectl apply -f x", CWD: "/w"}); err != nil {
		t.Fatal(err)
	}
	p, _ := Load(path)
	if err := Approve(path, p.Digest(), time.Now()); err != nil {
		t.Fatal(err)
	}
	var ran []string
	n, err := Apply(path, noCheck, func(e Entry) error {
		ran = append(ran, e.Command)
		return nil
	})
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if strings.Join(ran, ",") != "git push,kubectl apply -f x" {
		t.Errorf("ran = %q", ran)
	}
	p, _ = Load(path)
	if len(p.Pending()) != 0 || p.Approval != nil {
		t.Errorf("plan after apply = %+v", p)
	}
	if p.Entries[0].Status != Applied {
		t.Errorf("status = %q", p.Entries[0].Status)
	}
}

func TestApplyNeedsApproval(t *testing.T) {
	path := tmpPlan(t)
	if _, err := Apply(path, noCheck, nil); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty plan: %v", err)
	}
	if _, err := Add(path, Entry{Command: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(path, noCheck, nil); !errors.Is(err, ErrNotApproved) {
		t.Errorf("unapproved: %v", err)
	}
}

func TestApproveChecksDigest(t *testing.T) {
	path := tmpPlan(t)
	if err := Approve(path, "x", time.Now()); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty: %v", err)
	}
	if _, err := Add(path, Entry{Command: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := Approve(path, "wrong", time.Now()); !errors.Is(err, ErrChanged) {
		t.Errorf("wrong digest: %v", err)
	}
}

func TestAddVoidsApproval(t *testing.T) {
	path := tmpPlan(t)
	if _, err := Add(path, Entry{Command: "a"}); err != nil {
		t.Fatal(err)
	}
	p, _ := Load(path)
	if err := Approve(path, p.Digest(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(path, Entry{Command: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(path, noCheck, nil); !errors.Is(err, ErrNotApproved) {
		t.Errorf("apply after add: %v", err)
	}
}

func TestTamperingAfterApprovalIsCaught(t *testing.T) {
	path := tmpPlan(t)
	if _, err := Add(path, Entry{Command: "git status"}); err != nil {
		t.Fatal(err)
	}
	p, _ := Load(path)
	if err := Approve(path, p.Digest(), time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.ReplaceAll(string(data), "git status", "rm -rf /")
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = Apply(path, noCheck, func(Entry) error { called = true; return nil })
	if !errors.Is(err, ErrChanged) || called {
		t.Errorf("err=%v called=%v", err, called)
	}
}

func TestApplyStopsAtFailure(t *testing.T) {
	path := tmpPlan(t)
	for _, c := range []string{"a", "b", "c"} {
		if _, err := Add(path, Entry{Command: c}); err != nil {
			t.Fatal(err)
		}
	}
	p, _ := Load(path)
	if err := Approve(path, p.Digest(), time.Now()); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	var ran []string
	n, err := Apply(path, noCheck, func(e Entry) error {
		ran = append(ran, e.Command)
		if e.Command == "b" {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if strings.Join(ran, "") != "ab" {
		t.Errorf("ran = %q", ran)
	}
	p, _ = Load(path)
	got := []string{p.Entries[0].Status, p.Entries[1].Status, p.Entries[2].Status}
	if strings.Join(got, ",") != "applied,failed,pending" {
		t.Errorf("statuses = %q", got)
	}
	if p.Approval != nil {
		t.Error("a partial run must spend the approval")
	}
}

func TestApplyRechecks(t *testing.T) {
	path := tmpPlan(t)
	if _, err := Add(path, Entry{Command: "a"}); err != nil {
		t.Fatal(err)
	}
	p, _ := Load(path)
	if err := Approve(path, p.Digest(), time.Now()); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("denied by policy")
	called := false
	_, err := Apply(path, func(Entry) error { return denied }, func(Entry) error { called = true; return nil })
	if !errors.Is(err, denied) || called {
		t.Errorf("err=%v called=%v", err, called)
	}
}

func TestClear(t *testing.T) {
	path := tmpPlan(t)
	if _, err := Add(path, Entry{Command: "a"}); err != nil {
		t.Fatal(err)
	}
	n, err := Clear(path)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	p, _ := Load(path)
	if len(p.Entries) != 1 || len(p.Pending()) != 0 {
		t.Errorf("plan = %+v", p)
	}
}

func TestConcurrentAdds(t *testing.T) {
	path := tmpPlan(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Add(path, Entry{Command: "x"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 20 {
		t.Errorf("entries = %d", len(p.Entries))
	}
}

func TestDefaultPath(t *testing.T) {
	got, err := DefaultPath(func(string) string { return "/x" })
	if err != nil || got != "/x" {
		t.Errorf("%q %v", got, err)
	}
	got, err = DefaultPath(func(string) string { return "" })
	if err != nil || !strings.HasSuffix(got, filepath.Join(".seatbelt", "plan.json")) {
		t.Errorf("%q %v", got, err)
	}
}
