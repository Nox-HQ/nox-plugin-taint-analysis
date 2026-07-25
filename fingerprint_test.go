package main

import (
	"path/filepath"
	"testing"
)

// TestFingerprintIsPathIndependent pins the property the baseline depends on:
// the same finding, in the same file, must fingerprint identically no matter
// which directory the scan ran from.
//
// The walk hands us paths prefixed with workspaceRoot — a CI checkout, a
// developer's clone, a git worktree. When that prefix reached the fingerprint,
// a baseline captured in one location silently failed to suppress the same
// finding in another, and the gate then reported it as net-new.
func TestFingerprintIsPathIndependent(t *testing.T) {
	roots := []string{
		"/home/runner/work/mnemos/mnemos",
		"/Users/dev/code/mnemos",
		"/tmp/a-much-longer-worktree-name",
	}
	const relPath = "internal/kernel/evidence_sink.go"

	var want string
	for i, root := range roots {
		flow := &TaintFlow{
			RuleID:   "TAINT-004",
			FilePath: filepath.Join(root, relPath),
			FuncName: "newEvidenceSink",
			SinkLine: 70,
		}
		flow.Source.Line = 59

		got := fingerprint(flow, root)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("fingerprint changed with scan root:\n  root %q -> %q\n  root %q -> %q",
				roots[0], want, root, got)
		}
	}
}

// TestFingerprintStillDistinguishesFindings guards the other direction: making
// the fingerprint path-independent must not make genuinely different findings
// collide.
func TestFingerprintStillDistinguishesFindings(t *testing.T) {
	const root = "/repo"
	base := func() *TaintFlow {
		f := &TaintFlow{
			RuleID:   "TAINT-004",
			FilePath: "/repo/internal/a.go",
			FuncName: "openThing",
			SinkLine: 70,
		}
		f.Source.Line = 59
		return f
	}

	ref := fingerprint(base(), root)

	cases := map[string]func(*TaintFlow){
		"different file":     func(f *TaintFlow) { f.FilePath = "/repo/internal/b.go" },
		"different rule":     func(f *TaintFlow) { f.RuleID = "TAINT-002" },
		"different function": func(f *TaintFlow) { f.FuncName = "other" },
		"different sink":     func(f *TaintFlow) { f.SinkLine = 71 },
		"different source":   func(f *TaintFlow) { f.Source.Line = 60 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := base()
			mutate(f)
			if got := fingerprint(f, root); got == ref {
				t.Errorf("%s produced the same fingerprint %q — distinct findings must not collide", name, got)
			}
		})
	}
}

// TestReportPathNormalisesSeparators keeps Windows and Unix agreeing on one
// digest for the same file.
func TestReportPathNormalisesSeparators(t *testing.T) {
	got := reportPath("/repo", filepath.Join("/repo", "internal", "kernel", "sink.go"))
	if want := "internal/kernel/sink.go"; got != want {
		t.Errorf("reportPath = %q, want %q", got, want)
	}
	// A path outside the root, or an empty root, must degrade gracefully
	// rather than panic or emit a bare separator.
	if got := reportPath("", "/abs/path.go"); got != "/abs/path.go" {
		t.Errorf("empty root: got %q", got)
	}
}
