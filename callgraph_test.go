package main

import (
	"testing"
)

func TestCallGraph_AddFile(t *testing.T) {
	src := []byte(`package main

func foo(a string) {
	println(a)
}

func bar(x, y int) string {
	return "ok"
}
`)
	cg := NewCallGraph()
	if err := cg.AddFile("test.go", src); err != nil {
		t.Fatalf("AddFile: %v", err)
	}

	if len(cg.Funcs) != 2 {
		t.Fatalf("expected 2 functions, got %d", len(cg.Funcs))
	}

	fooInfo := cg.Funcs["foo"]
	if fooInfo == nil {
		t.Fatal("expected function 'foo' in call graph")
	}
	if len(fooInfo.Params) != 1 || fooInfo.Params[0] != "a" {
		t.Errorf("foo params: got %v, want [a]", fooInfo.Params)
	}

	barInfo := cg.Funcs["bar"]
	if barInfo == nil {
		t.Fatal("expected function 'bar' in call graph")
	}
	if len(barInfo.Params) != 2 {
		t.Errorf("bar params: got %v, want [x y]", barInfo.Params)
	}
}

func TestInterproceduralGo_SQLInjection(t *testing.T) {
	handler := []byte(`package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	runQuery(id)
}
`)
	sink := []byte(`package main

import "database/sql"

func runQuery(userID string) {
	db, _ := sql.Open("postgres", "")
	db.Exec("SELECT * FROM users WHERE id=" + userID)
}
`)

	files := map[string][]byte{
		"handler.go": handler,
		"db.go":      sink,
	}

	flows := AnalyzeGoFileInterprocedural(files)

	var found bool
	for _, f := range flows {
		if f.RuleID == "TAINT-006" {
			found = true
			if f.Source.Kind != "http_query" {
				t.Errorf("expected source kind http_query, got %s", f.Source.Kind)
			}
			if f.CWE != "CWE-89" {
				t.Errorf("expected CWE-89, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected TAINT-006 (cross-function SQL injection)")
	}
}

func TestInterproceduralGo_CommandInjection(t *testing.T) {
	handler := []byte(`package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	executeCommand(cmd)
}
`)
	sink := []byte(`package main

import "os/exec"

func executeCommand(command string) {
	exec.Command("sh", "-c", command)
}
`)

	files := map[string][]byte{
		"handler.go": handler,
		"cmd.go":     sink,
	}

	flows := AnalyzeGoFileInterprocedural(files)

	var found bool
	for _, f := range flows {
		if f.RuleID == "TAINT-007" {
			found = true
			if f.CWE != "CWE-78" {
				t.Errorf("expected CWE-78, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected TAINT-007 (cross-function command injection)")
	}
}

func TestInterproceduralGo_NoFinding_SafeFunc(t *testing.T) {
	handler := []byte(`package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	safeFunc(id)
}
`)
	safe := []byte(`package main

func safeFunc(data string) string {
	return "processed: " + data
}
`)

	files := map[string][]byte{
		"handler.go": handler,
		"safe.go":    safe,
	}

	flows := AnalyzeGoFileInterprocedural(files)

	for _, f := range flows {
		if f.RuleID == "TAINT-006" || f.RuleID == "TAINT-007" {
			t.Errorf("unexpected interprocedural finding: %s", f.RuleID)
		}
	}
}

func TestInterproceduralGo_DepthLimit(t *testing.T) {
	// Chain of 4 functions deep — should stop at depth 3.
	src := []byte(`package main

import (
	"net/http"
	"database/sql"
)

func level0(w http.ResponseWriter, r *http.Request) {
	x := r.URL.Query().Get("x")
	level1(x)
}

func level1(a string) {
	level2(a)
}

func level2(b string) {
	level3(b)
}

func level3(c string) {
	db, _ := sql.Open("postgres", "")
	db.Exec("SELECT " + c)
}
`)

	files := map[string][]byte{"deep.go": src}
	flows := AnalyzeGoFileInterprocedural(files)

	// Should find the flow even at depth 3 (level0→level1→level2→level3).
	// But level3 is at depth 3 from level0's perspective.
	// level0 calls level1 (depth 1), level1 calls level2 (depth 2),
	// level2 calls level3 (depth 3 = maxCallDepth), so it should still be found.
	var found bool
	for _, f := range flows {
		if f.RuleID == "TAINT-006" {
			found = true
		}
	}
	if !found {
		t.Error("expected TAINT-006 through 3-level call chain")
	}
}

func TestTaintContext_Push(t *testing.T) {
	ctx := NewTaintContext()
	ctx.Stack = []string{"main"}

	child := ctx.Push("helper")
	if child.Depth != 1 {
		t.Errorf("expected depth 1, got %d", child.Depth)
	}
	if len(child.Stack) != 2 {
		t.Errorf("expected stack length 2, got %d", len(child.Stack))
	}
	if child.Stack[0] != "main" || child.Stack[1] != "helper" {
		t.Errorf("unexpected stack: %v", child.Stack)
	}

	// Original context should be unchanged.
	if ctx.Depth != 0 {
		t.Errorf("original context depth should be 0, got %d", ctx.Depth)
	}
}

func TestTaintContext_CanDescend(t *testing.T) {
	ctx := NewTaintContext()
	if !ctx.CanDescend() {
		t.Error("depth 0 should be able to descend")
	}

	deep := ctx
	for i := 0; i < maxCallDepth; i++ {
		deep = deep.Push("f")
	}
	if deep.CanDescend() {
		t.Error("should not descend past maxCallDepth")
	}
}

func TestDeduplicateFlows(t *testing.T) {
	flows := []TaintFlow{
		{RuleID: "TAINT-001", FilePath: "a.go", FuncName: "f", Source: TaintSource{Line: 1}, SinkLine: 5},
		{RuleID: "TAINT-001", FilePath: "a.go", FuncName: "f", Source: TaintSource{Line: 1}, SinkLine: 5},
		{RuleID: "TAINT-002", FilePath: "a.go", FuncName: "f", Source: TaintSource{Line: 1}, SinkLine: 5},
	}

	result := deduplicateFlows(flows)
	if len(result) != 2 {
		t.Errorf("expected 2 unique flows, got %d", len(result))
	}
}

func TestTextCallGraph_PythonInterproc(t *testing.T) {
	caller := []byte(`from flask import request
import subprocess

def handle_request():
    cmd = request.args.get("cmd")
    run_command(cmd)

def run_command(user_cmd):
    subprocess.run(user_cmd, shell=True)
`)

	files := map[string][]byte{
		"app.py": caller,
	}

	flows := AnalyzeTextFilesInterprocedural(files, "python")

	var found bool
	for _, f := range flows {
		if f.RuleID == "TAINT-007" {
			found = true
		}
	}
	if !found {
		t.Error("expected TAINT-007 (cross-function command injection) in Python")
	}
}

func TestTextCallGraph_JSInterproc(t *testing.T) {
	caller := []byte(`function handleRequest(req, res) {
    const cmd = req.query.cmd;
    runCommand(cmd);
}

function runCommand(userCmd) {
    child_process.exec(userCmd);
}
`)

	files := map[string][]byte{
		"app.js": caller,
	}

	flows := AnalyzeTextFilesInterprocedural(files, "javascript")

	var found bool
	for _, f := range flows {
		if f.RuleID == "TAINT-007" {
			found = true
		}
	}
	if !found {
		t.Error("expected TAINT-007 (cross-function command injection) in JavaScript")
	}
}

func TestParseParamList(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a, b, c", []string{"a", "b", "c"}},
		{"self, name: str, age: int = 0", []string{"name", "age"}},
		{"x", []string{"x"}},
		{"", nil},
		{"req, res", []string{"req", "res"}},
	}

	for _, tt := range tests {
		got := parseParamList(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseParamList(%q): got %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseParamList(%q)[%d]: got %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}
