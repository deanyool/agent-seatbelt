//go:build windows

package shell

import "os/exec"

func isolate(*exec.Cmd) {}

func reap(*exec.Cmd) {}
