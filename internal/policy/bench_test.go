package policy

import "testing"

func benchEvaluate(b *testing.B, src string) {
	p, err := Default()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		p.Evaluate(src, Options{CWD: "/work"})
	}
}

func BenchmarkSimple(b *testing.B) { benchEvaluate(b, "git status") }

func BenchmarkChain(b *testing.B) {
	benchEvaluate(b, `FOO=1 git log --oneline | grep "fix" && kubectl -n prod get pods -o yaml; echo "$(date)"`)
}

func BenchmarkHeredoc(b *testing.B) {
	benchEvaluate(b, "git commit -m \"$(cat <<'EOF'\nA longer commit message\n\nWith a body.\nEOF\n)\"")
}

func BenchmarkLoadDefault(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Default(); err != nil {
			b.Fatal(err)
		}
	}
}
