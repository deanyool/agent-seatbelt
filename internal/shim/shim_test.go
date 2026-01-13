package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExe(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestInstallAndList(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(root, "seatbelt")
	writeExe(t, self)
	dir := filepath.Join(root, "shims")

	if err := Install(dir, self, []string{"git", "kubectl"}); err != nil {
		t.Fatal(err)
	}
	// Installing again is a no-op.
	if err := Install(dir, self, []string{"git"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := List(dir, self)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "git,kubectl" {
		t.Errorf("names = %q", names)
	}
}

func TestListMissingDir(t *testing.T) {
	names, err := List(filepath.Join(t.TempDir(), "absent"), "/x")
	if err != nil || names != nil {
		t.Errorf("names=%q err=%v", names, err)
	}
}

func TestInstallRefusesToReplace(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(root, "seatbelt")
	writeExe(t, self)
	dir := filepath.Join(root, "shims")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExe(t, filepath.Join(dir, "git"))
	if err := os.Symlink("/somewhere/else", filepath.Join(dir, "gh")); err != nil {
		t.Fatal(err)
	}
	if err := Install(dir, self, []string{"git"}); err == nil {
		t.Error("want an error for a real file")
	}
	if err := Install(dir, self, []string{"gh"}); err == nil {
		t.Error("want an error for a foreign symlink")
	}
}

func TestInstallRejectsBadNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"", "a/b", "../git"} {
		if err := Install(root, "/x", []string{name}); err == nil {
			t.Errorf("want an error for %q", name)
		}
	}
}

func TestResolveSkipsTheShim(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(root, "seatbelt")
	writeExe(t, self)
	shims := filepath.Join(root, "shims")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Install(shims, self, []string{"git"}); err != nil {
		t.Fatal(err)
	}
	writeExe(t, filepath.Join(bin, "git"))

	path := strings.Join([]string{shims, bin}, string(os.PathListSeparator))
	got, err := Resolve("git", self, path)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(bin, "git") {
		t.Errorf("got %q", got)
	}
}

func TestResolveSkipsNonExecutablesAndDirectories(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(root, "seatbelt")
	writeExe(t, self)
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	c := filepath.Join(root, "c")
	for _, d := range []string{a, b, c, filepath.Join(b, "tool")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(a, "tool"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeExe(t, filepath.Join(c, "tool"))
	path := strings.Join([]string{a, b, c}, string(os.PathListSeparator))
	got, err := Resolve("tool", self, path)
	if err != nil || got != filepath.Join(c, "tool") {
		t.Errorf("got %q err %v", got, err)
	}
}

func TestResolveNotFound(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(root, "seatbelt")
	writeExe(t, self)
	if _, err := Resolve("nope", self, root); err == nil {
		t.Error("want an error")
	}
	if _, err := Resolve("nope", filepath.Join(root, "absent"), root); err == nil {
		t.Error("want an error when seatbelt itself is missing")
	}
}

func TestDefaultDir(t *testing.T) {
	dir, err := DefaultDir()
	if err != nil || !strings.HasSuffix(dir, filepath.Join(".seatbelt", "shims")) {
		t.Errorf("%q %v", dir, err)
	}
}
