package policy

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// windowsPaths switches protected-path matching to Windows rules. It is a variable
// so tests can check those rules on any system.
var windowsPaths = runtime.GOOS == "windows"

// expandPathPattern resolves ~ and makes a relative pattern match at any depth, so
// .git/hooks/* covers every repository.
func expandPathPattern(s, home string) string {
	if windowsPaths {
		return expandWindowsPattern(s, home)
	}
	switch {
	case s == "~":
		return home
	case strings.HasPrefix(s, "~/"):
		return filepath.Join(home, s[2:])
	case strings.HasPrefix(s, "re:"), strings.HasPrefix(s, "/"):
		return s
	}
	return "*/" + s
}

func (p *Policy) resolvePath(path, cwd string) string {
	if windowsPaths {
		return resolveWindowsPath(path, cwd, p.home)
	}
	switch {
	case path == "~":
		path = p.home
	case strings.HasPrefix(path, "~/"):
		path = filepath.Join(p.home, path[2:])
	case !filepath.IsAbs(path):
		if cwd == "" {
			cwd = "/"
		}
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path)
}

// On Windows, paths are compared with forward slashes and in lower case, since the
// file system ignores case. The Bash tool in Claude Code runs Git Bash there, so a
// command can name C:\Users\me as C:/Users/me or as /c/Users/me, and all three must
// meet the same pattern.

func expandWindowsPattern(s, home string) string {
	if strings.HasPrefix(s, "re:") {
		return s
	}
	s = strings.ReplaceAll(s, `\`, "/")
	home = windowsSlash(home)
	switch {
	case s == "~":
		s = home
	case strings.HasPrefix(s, "~/"):
		s = home + "/" + s[2:]
	case windowsAbs(s):
	default:
		s = "*/" + s
	}
	return strings.ToLower(s)
}

func resolveWindowsPath(p, cwd, home string) string {
	p = windowsSlash(p)
	switch {
	case p == "~":
		p = windowsSlash(home)
	case strings.HasPrefix(p, "~/"):
		p = windowsSlash(home) + "/" + p[2:]
	case windowsAbs(p):
	case strings.HasPrefix(p, "/"):
		// Rooted but with no drive: the drive of the working directory.
		if c := windowsSlash(cwd); len(c) >= 2 && c[1] == ':' {
			p = c[:2] + p
		}
	default:
		c := windowsSlash(cwd)
		if c == "" {
			c = "/"
		}
		p = c + "/" + p
	}
	return strings.ToLower(windowsClean(p))
}

// windowsSlash turns backslashes into slashes and Git Bash's /c/... into c:/....
func windowsSlash(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) >= 2 && p[0] == '/' && isLetter(p[1]) && (len(p) == 2 || p[2] == '/') {
		p = p[1:2] + ":" + p[2:]
		if len(p) == 2 {
			p += "/"
		}
	}
	return p
}

// windowsAbs reports whether a slashed path names a drive or a UNC share.
func windowsAbs(p string) bool {
	return (len(p) >= 3 && isLetter(p[0]) && p[1] == ':' && p[2] == '/') || strings.HasPrefix(p, "//")
}

// windowsClean is path.Clean that keeps a drive letter and a UNC prefix intact.
func windowsClean(p string) string {
	switch {
	case len(p) >= 2 && isLetter(p[0]) && p[1] == ':':
		return p[:2] + path.Clean("/"+p[2:])
	case strings.HasPrefix(p, "//"):
		return "/" + path.Clean(p[1:])
	}
	return path.Clean(p)
}

func isLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
