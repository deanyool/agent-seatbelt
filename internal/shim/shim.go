// Package shim implements shell shim mode. A shim is a symlink named after a real
// program, in a directory placed first on PATH. When it runs, seatbelt checks the
// call and then hands over to the real program.
package shim

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrNotFound means no real program exists behind a shim.
var ErrNotFound = errors.New("not found on PATH")

// DefaultDir returns where shims live unless told otherwise.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".seatbelt", "shims"), nil
}

// Install creates one symlink per name. It refuses to replace a file that is not
// already a shim pointing at self.
func Install(dir, self string, names []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range names {
		if name == "" || strings.ContainsRune(name, '/') {
			return fmt.Errorf("invalid program name %q", name)
		}
		link := filepath.Join(dir, name)
		target, err := os.Readlink(link)
		switch {
		case err == nil && target == self:
			continue
		case err == nil:
			return fmt.Errorf("%s already points at %s", link, target)
		case errors.Is(err, fs.ErrNotExist):
		default:
			return fmt.Errorf("%s already exists and is not a shim", link)
		}
		if err := os.Symlink(self, link); err != nil {
			return err
		}
	}
	return nil
}

// List returns the names of the shims in dir that point at self.
func List(dir, self string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil && target == self {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Resolve finds the real program behind a shim: the first match on PATH that isn't
// seatbelt itself. Comparing files rather than names is what stops a shim from
// finding itself and looping forever.
func Resolve(name, self, path string) (string, error) {
	selfInfo, err := os.Stat(self)
	if err != nil {
		return "", err
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		if os.SameFile(info, selfInfo) {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%s: %w", name, ErrNotFound)
}
