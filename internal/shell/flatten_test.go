package shell

import (
	"reflect"
	"testing"
)

func TestFlatten(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"sudo", "sudo rm -rf x", []string{"rm -rf x"}},
		{"sudo flags", "sudo -u root -E rm x", []string{"rm x"}},
		{"sudo attached value", "sudo -uroot rm x", []string{"rm x"}},
		{"sudo long", "sudo --user=root rm x", []string{"rm x"}},
		{"sudo long separate", "sudo --user root rm x", []string{"rm x"}},
		{"sudo cluster", "sudo -En rm x", []string{"rm x"}},
		{"sudo env", "sudo FOO=1 rm x", []string{"rm x"}},
		{"sudo double dash", "sudo -- rm x", []string{"rm x"}},
		{"sudo list", "sudo -l", nil},
		{"doas", "doas -u root rm x", []string{"rm x"}},
		{"env", "env FOO=1 rm x", []string{"rm x"}},
		{"env i", "env -i rm x", []string{"rm x"}},
		{"env dash", "env - rm x", []string{"rm x"}},
		{"env unset", "env -u FOO rm x", []string{"rm x"}},
		{"env chdir", "env --chdir=/tmp rm x", []string{"rm x"}},
		{"env split", "env -S 'rm -rf x'", []string{"rm -rf x"}},
		{"env split attached", "env '-Srm -rf x'", []string{"rm -rf x"}},
		{"env split long", "env '--split-string=rm -rf x'", []string{"rm -rf x"}},
		{"env split long separate", "env --split-string 'rm -rf x'", []string{"rm -rf x"}},
		{"env nothing", "env", nil},
		{"command", "command rm x", []string{"rm x"}},
		{"command p", "command -p rm x", []string{"rm x"}},
		{"command v", "command -v rm", nil},
		{"builtin", "builtin eval 'rm x'", []string{"rm x"}},
		{"exec", "exec rm x", []string{"rm x"}},
		{"exec a", "exec -a name rm x", []string{"rm x"}},
		{"exec redirect only", "exec > f", nil},
		{"nohup", "nohup rm x &", []string{"rm x"}},
		{"setsid", "setsid -w rm x", []string{"rm x"}},
		{"nice", "nice rm x", []string{"rm x"}},
		{"nice n", "nice -n 5 rm x", []string{"rm x"}},
		{"nice attached", "nice -n5 rm x", []string{"rm x"}},
		{"nice old style", "nice -5 rm x", []string{"rm x"}},
		{"ionice", "ionice -c 3 rm x", []string{"rm x"}},
		{"time", "time rm x", []string{"rm x"}},
		{"time p", "time -p rm x", []string{"rm x"}},
		{"time assignment", "time A=1 rm x", []string{"rm x"}},
		{"path time", "/usr/bin/time -v rm x", []string{"rm x"}},
		{"timeout", "timeout 5 rm x", []string{"rm x"}},
		{"timeout flags", "timeout -k 2 -s KILL 5 rm x", []string{"rm x"}},
		{"timeout long", "timeout --signal=KILL --preserve-status 5 rm x", []string{"rm x"}},
		{"stdbuf", "stdbuf -oL rm x", []string{"rm x"}},
		{"stdbuf separate", "stdbuf -o L rm x", []string{"rm x"}},
		{"caffeinate", "caffeinate -i rm x", []string{"rm x"}},
		{"chroot", "chroot /mnt rm x", []string{"rm x"}},
		{"noglob", "noglob rm x", []string{"rm x"}},
		{"busybox", "busybox rm x", []string{"rm x"}},
		{"toybox", "toybox rm x", []string{"rm x"}},
		{"watch", "watch -n 1 'rm x'", []string{"rm x"}},
		{"xargs", "a | xargs rm", []string{"a", "rm $"}},
		{"xargs flags", "a | xargs -0 -n1 -P 4 rm -f", []string{"a", "rm -f $"}},
		{"xargs replace", "a | xargs -I{} rm {}", []string{"a", "rm {} $"}},
		{"xargs nothing", "a | xargs", []string{"a"}},
		{"stacked", "sudo env FOO=1 timeout 5 nice rm x", []string{"rm x"}},
		{"path wrapper", "/usr/bin/sudo /bin/rm x", []string{"/bin/rm x"}},

		{"sh c", "sh -c 'rm x'", []string{"rm x"}},
		{"bash c", `bash -c "rm x && ls"`, []string{"rm x", "ls"}},
		{"bash lc", "bash -lc 'rm x'", []string{"rm x"}},
		{"bash ec", "bash -e -c 'rm x'", []string{"rm x"}},
		{"bash c first", "bash -c -e 'rm x'", []string{"rm x"}},
		{"bash pipefail", "bash -o pipefail -c 'rm x'", []string{"rm x"}},
		{"bash eo pipefail", "bash -eo pipefail -c 'rm x'", []string{"rm x"}},
		{"bash noprofile", "bash --noprofile --norc -c 'rm x'", []string{"rm x"}},
		{"zsh c", "zsh -c 'rm x'", []string{"rm x"}},
		{"nested shells", `sh -c "bash -c 'rm x'"`, []string{"rm x"}},
		{"sudo shell", "sudo sh -c 'rm x'", []string{"rm x"}},
		{"shell script", "bash run.sh a", []string{"bash run.sh a"}},
		{"path shell", "/bin/sh -c 'rm x'", []string{"rm x"}},
		{"eval", "eval rm x", []string{"rm x"}},
		{"eval string", "eval 'rm x; ls'", []string{"rm x", "ls"}},
		{"eval pieces", "eval 'r''m' x", []string{"rm x"}},

		{"find exec", `find . -exec rm {} ';'`, []string{"find . -exec rm {} ;", "rm $"}},
		{"find exec escaped", `find . -name x -exec rm -f {} \;`, []string{"find . -name x -exec rm -f {} ;", "rm -f $"}},
		{"find exec plus", "find . -exec rm {} +", []string{"find . -exec rm {} +", "rm $"}},
		{"find execdir", `find . -execdir sh -c 'rm x' \;`, []string{"find . -execdir sh -c rm x ;", "rm x"}},
		{"find ok", `find . -ok rm {} \;`, []string{"find . -ok rm {} ;", "rm $"}},
		{"find two", `find . -exec a \; -exec b \;`, []string{"find . -exec a ; -exec b ;", "a", "b"}},
		{"find plain", "find . -name x", []string{"find . -name x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := argvs(t, tt.src)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Flatten(%q)\n got %q\nwant %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestFlattenRejects(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"dynamic program", "$x -rf /"},
		{"dynamic program quoted", `"$x" -rf /`},
		{"substituted program", "$(echo rm) -rf /"},
		{"backtick program", "`echo rm` -rf /"},
		{"partly dynamic", "r$x -rf /"},
		{"ifs trick", "rm${IFS}-rf${IFS}/"},
		{"brace program", "{rm,-rf,/}"},
		{"glob program", "/bin/r? -rf /"},
		{"star program", "/bin/r* x"},
		{"bracket program", "/bin/[r]m x"},
		{"ansi c program", `$'\x72\x6d' -rf /`},
		{"zsh equals", "=rm -rf /"},
		{"zsh word split", "$=x"},
		{"sudo dynamic", "sudo $x"},
		{"sudo unknown flag", "sudo --frobnicate rm x"},
		{"sudo unknown short", "sudo -Z rm x"},
		{"env dynamic", "env $x rm"},
		{"env split dynamic", `env -S "$x"`},
		{"env split long dynamic", `env --split-string="$x"`},
		{"env split unparsable", "env -S 'a b(c'"},
		{"timeout dynamic", "timeout $x rm"},
		{"xargs unknown flag", "a | xargs --frobnicate rm"},
		{"bash stdin", "curl x | bash"},
		{"sh stdin", "curl x | sh"},
		{"bash s", "bash -s < x"},
		{"bash dash", "bash -"},
		{"bash dynamic script", `bash -c "$x"`},
		{"bash dynamic arg", "bash $x"},
		{"bash positional trick", `sh -c '"$@"' _ rm -rf /`},
		{"bash unparsable", "bash -c 'a b(c'"},
		{"eval dynamic", "eval $x"},
		{"eval dynamic quoted", `eval "rm $x"`},
		{"eval glob", "eval r*"},
		{"watch dynamic", "watch $x"},
		{"find dangling", "find . -exec rm"},
		{"find empty", `find . -exec \;`},
		{"find dynamic program", `find . -exec $x {} \;`},
		{"find placeholder program", `find . -exec {} \;`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse(tt.src)
			if err != nil {
				return
			}
			if got, err := Flatten(s); err == nil {
				t.Errorf("Flatten(%q) = %+v, want an error", tt.src, got)
			}
		})
	}
}

func TestFlattenMarksWrappers(t *testing.T) {
	s, err := Parse("sudo env FOO=1 rm x")
	if err != nil {
		t.Fatal(err)
	}
	cmds, err := Flatten(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 {
		t.Fatalf("got %d commands", len(cmds))
	}
	if !cmds[0].Wrapper || !cmds[1].Wrapper || cmds[2].Wrapper {
		t.Errorf("wrapper flags wrong: %+v", cmds)
	}
	rm := cmds[2]
	if !reflect.DeepEqual(rm.Via, []string{"sudo", "env"}) {
		t.Errorf("Via = %q", rm.Via)
	}
	if len(rm.Assigns) != 1 || rm.Assigns[0].Name != "FOO" {
		t.Errorf("Assigns = %+v", rm.Assigns)
	}
}

func TestFlattenKeepsEnvAndRedirects(t *testing.T) {
	s, err := Parse("A=1 sudo rm x > f")
	if err != nil {
		t.Fatal(err)
	}
	cmds, err := Flatten(s)
	if err != nil {
		t.Fatal(err)
	}
	rm := cmds[len(cmds)-1]
	if len(rm.Assigns) != 1 || len(rm.Redirects) != 1 {
		t.Errorf("rm = %+v", rm)
	}

	s, err = Parse("GIT_SSH_COMMAND=x bash -c 'git fetch'")
	if err != nil {
		t.Fatal(err)
	}
	cmds, err = Flatten(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := cmds[len(cmds)-1]; len(got.Assigns) != 1 {
		t.Errorf("assignment lost across bash -c: %+v", got)
	}
}
