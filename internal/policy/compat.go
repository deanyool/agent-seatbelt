package policy

// Result is the old yes-or-no answer, kept until the callers move to Report.
type Result struct {
	Allowed bool
	Reason  string
}

// Check evaluates a line and flattens the report.
func (p *Policy) Check(line string) Result {
	rep := p.Evaluate(line, Options{})
	if rep.Decision == Allow {
		return Result{Allowed: true}
	}
	return Result{Reason: rep.Reason()}
}
