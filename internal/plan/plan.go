// Package plan implements plan-then-commit: writes are queued in a file, a person
// reviews and approves that exact list, and only then does it run.
package plan

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Status values for a plan entry.
const (
	Pending = "pending"
	Applied = "applied"
	Failed  = "failed"
)

// Entry is one queued command.
type Entry struct {
	ID      string    `json:"id"`
	Command string    `json:"command"`
	CWD     string    `json:"cwd,omitempty"`
	Source  string    `json:"source,omitempty"`
	Rule    string    `json:"rule,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	AddedAt time.Time `json:"added_at"`
	Status  string    `json:"status"`
}

// Approval records that a person accepted one exact list of commands.
type Approval struct {
	Digest string    `json:"digest"`
	At     time.Time `json:"at"`
}

// Plan is the contents of a plan file.
type Plan struct {
	Version  int       `json:"version"`
	Entries  []Entry   `json:"entries"`
	Approval *Approval `json:"approval,omitempty"`
}

// Errors returned by Approve and Apply.
var (
	ErrNotApproved = errors.New("the plan has not been approved")
	ErrChanged     = errors.New("the plan changed after it was approved")
	ErrEmpty       = errors.New("the plan has nothing pending")
)

// DefaultPath returns SEATBELT_PLAN, or ~/.seatbelt/plan.json.
func DefaultPath(getenv func(string) string) (string, error) {
	if v := getenv("SEATBELT_PLAN"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".seatbelt", "plan.json"), nil
}

// Load reads a plan. A missing file is an empty plan.
func Load(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Plan{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported plan version %d", path, p.Version)
	}
	return &p, nil
}

func save(path string, p *Plan) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// withLock runs fn while holding an exclusive lock, so hooks firing at the same
// time can't lose each other's entries.
func withLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		return err
	}
	defer func() { _ = unlockFile(lock) }()
	return fn()
}

// Add queues a command and returns its ID. Adding always voids an earlier
// approval, because the approved list is no longer the list.
func Add(path string, e Entry) (Entry, error) {
	err := withLock(path, func() error {
		p, err := Load(path)
		if err != nil {
			return err
		}
		id, err := newID()
		if err != nil {
			return err
		}
		e.ID = id
		e.Status = Pending
		if e.AddedAt.IsZero() {
			e.AddedAt = time.Now()
		}
		e.AddedAt = e.AddedAt.UTC()
		p.Entries = append(p.Entries, e)
		p.Approval = nil
		return save(path, p)
	})
	return e, err
}

func newID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Pending returns the entries that have not run.
func (p *Plan) Pending() []Entry {
	var out []Entry
	for _, e := range p.Entries {
		if e.Status == Pending {
			out = append(out, e)
		}
	}
	return out
}

// Digest fingerprints the pending commands and where they would run.
func (p *Plan) Digest() string {
	h := sha256.New()
	for _, e := range p.Pending() {
		fmt.Fprintf(h, "%d:%s\x00%d:%s\x00%d:%s\x00", len(e.ID), e.ID, len(e.CWD), e.CWD, len(e.Command), e.Command)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Approve marks the plan approved, but only if digest is what's in the file now.
func Approve(path, digest string, at time.Time) error {
	return withLock(path, func() error {
		p, err := Load(path)
		if err != nil {
			return err
		}
		if len(p.Pending()) == 0 {
			return ErrEmpty
		}
		if p.Digest() != digest {
			return ErrChanged
		}
		p.Approval = &Approval{Digest: digest, At: at.UTC()}
		return save(path, p)
	})
}

// Apply runs the pending entries in order, stopping at the first failure. check
// runs right before each command, so a rule tightened after approval still holds.
// The approval is spent whether or not everything succeeded.
func Apply(path string, check, run func(Entry) error) (ran int, err error) {
	err = withLock(path, func() error {
		p, err := Load(path)
		if err != nil {
			return err
		}
		if len(p.Pending()) == 0 {
			return ErrEmpty
		}
		if p.Approval == nil {
			return ErrNotApproved
		}
		if p.Approval.Digest != p.Digest() {
			return ErrChanged
		}
		p.Approval = nil
		for i := range p.Entries {
			e := &p.Entries[i]
			if e.Status != Pending {
				continue
			}
			if err := check(*e); err != nil {
				e.Status = Failed
				return errors.Join(fmt.Errorf("%s: %w", e.ID, err), save(path, p))
			}
			if err := run(*e); err != nil {
				e.Status = Failed
				return errors.Join(fmt.Errorf("%s: %w", e.ID, err), save(path, p))
			}
			e.Status = Applied
			ran++
			if err := save(path, p); err != nil {
				return err
			}
		}
		return nil
	})
	return ran, err
}

// Clear marks every pending entry failed, so nothing runs but the record stays.
func Clear(path string) (int, error) {
	n := 0
	err := withLock(path, func() error {
		p, err := Load(path)
		if err != nil {
			return err
		}
		for i := range p.Entries {
			if p.Entries[i].Status == Pending {
				p.Entries[i].Status = Failed
				n++
			}
		}
		p.Approval = nil
		return save(path, p)
	})
	return n, err
}
