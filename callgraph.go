package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// FuncInfo holds parsed information about a Go function.
type FuncInfo struct {
	Name     string
	Decl     *ast.FuncDecl
	FilePath string
	// Params lists parameter names in order.
	Params []string
	// ReturnsTaint tracks if the function returns a tainted value
	// (populated during analysis).
	ReturnsTaint bool
}

// CallGraph maps function names to their parsed info across a package.
type CallGraph struct {
	Funcs map[string]*FuncInfo
	fset  *token.FileSet
}

// NewCallGraph creates an empty call graph.
func NewCallGraph() *CallGraph {
	return &CallGraph{
		Funcs: make(map[string]*FuncInfo),
		fset:  token.NewFileSet(),
	}
}

// AddFile parses a Go file and indexes all function declarations.
func (cg *CallGraph) AddFile(filePath string, content []byte) error {
	file, err := parser.ParseFile(cg.fset, filePath, content, 0)
	if err != nil {
		return err
	}

	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fn.Body == nil {
			return false
		}

		info := &FuncInfo{
			Name:     fn.Name.Name,
			Decl:     fn,
			FilePath: filePath,
			Params:   extractParamNames(fn),
		}
		cg.Funcs[fn.Name.Name] = info
		return false
	})

	return nil
}

// Fset returns the file set used for position tracking.
func (cg *CallGraph) Fset() *token.FileSet {
	return cg.fset
}

// extractParamNames returns the parameter names from a function declaration.
func extractParamNames(fn *ast.FuncDecl) []string {
	if fn.Type.Params == nil {
		return nil
	}
	var names []string
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	return names
}

// maxCallDepth is the maximum depth for interprocedural analysis.
const maxCallDepth = 3

// TaintContext tracks taint state across function calls.
type TaintContext struct {
	// Stack holds the call chain for reporting.
	Stack []string
	// Depth is the current call depth (0 = top-level).
	Depth int
}

// NewTaintContext creates a new context at the root level.
func NewTaintContext() *TaintContext {
	return &TaintContext{
		Stack: nil,
		Depth: 0,
	}
}

// Push adds a function call to the context stack.
func (tc *TaintContext) Push(funcName string) *TaintContext {
	newStack := make([]string, len(tc.Stack)+1)
	copy(newStack, tc.Stack)
	newStack[len(tc.Stack)] = funcName
	return &TaintContext{
		Stack: newStack,
		Depth: tc.Depth + 1,
	}
}

// CanDescend reports whether we can go deeper in the call chain.
func (tc *TaintContext) CanDescend() bool {
	return tc.Depth < maxCallDepth
}

// CallChain returns the call chain as a readable string.
func (tc *TaintContext) CallChain() string {
	return strings.Join(tc.Stack, " -> ")
}

// AnalyzeGoFileInterprocedural performs interprocedural taint analysis on Go files
// within the same package/directory.
func AnalyzeGoFileInterprocedural(files map[string][]byte) []TaintFlow {
	cg := NewCallGraph()

	// Phase 1: Index all functions.
	for path, content := range files {
		_ = cg.AddFile(path, content)
	}

	// Phase 2: Run intraprocedural analysis first, then follow calls.
	var flows []TaintFlow

	for _, info := range cg.Funcs {
		ctx := NewTaintContext()
		ctx.Stack = []string{info.Name}
		funcFlows := analyzeGoFuncInterproc(cg, info, nil, ctx)
		flows = append(flows, funcFlows...)
	}

	return deduplicateFlows(flows)
}

// analyzeGoFuncInterproc analyzes a function with interprocedural call following.
// taintedParams maps parameter indices to their taint sources from callers.
func analyzeGoFuncInterproc(cg *CallGraph, info *FuncInfo, taintedParams map[int]TaintSource, ctx *TaintContext) []TaintFlow {
	state := NewTaintState()

	// Mark parameters as tainted if they were tainted by the caller.
	for idx, src := range taintedParams {
		if idx < len(info.Params) {
			state.Mark(info.Params[idx], src)
		}
	}

	var flows []TaintFlow
	for _, stmt := range info.Decl.Body.List {
		flows = append(flows, analyzeGoStmtInterproc(cg, cg.Fset(), info.FilePath, info.Name, stmt, state, ctx)...)
	}
	return flows
}

// analyzeGoStmtInterproc extends analyzeGoStmt with interprocedural call following.
func analyzeGoStmtInterproc(cg *CallGraph, fset *token.FileSet, filePath, funcName string, stmt ast.Stmt, state *TaintState, ctx *TaintContext) []TaintFlow {
	var flows []TaintFlow

	switch s := stmt.(type) {
	case *ast.AssignStmt:
		flows = append(flows, analyzeGoAssignInterproc(cg, fset, filePath, funcName, s, state, ctx)...)

	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			flows = append(flows, analyzeGoCallInterproc(cg, fset, filePath, funcName, call, state, ctx)...)
		}

	case *ast.IfStmt:
		if s.Body != nil {
			for _, inner := range s.Body.List {
				flows = append(flows, analyzeGoStmtInterproc(cg, fset, filePath, funcName, inner, state, ctx)...)
			}
		}
		if s.Else != nil {
			flows = append(flows, analyzeGoStmtInterproc(cg, fset, filePath, funcName, s.Else, state, ctx)...)
		}

	case *ast.BlockStmt:
		for _, inner := range s.List {
			flows = append(flows, analyzeGoStmtInterproc(cg, fset, filePath, funcName, inner, state, ctx)...)
		}

	case *ast.ForStmt:
		if s.Body != nil {
			for _, inner := range s.Body.List {
				flows = append(flows, analyzeGoStmtInterproc(cg, fset, filePath, funcName, inner, state, ctx)...)
			}
		}

	case *ast.RangeStmt:
		if s.Body != nil {
			for _, inner := range s.Body.List {
				flows = append(flows, analyzeGoStmtInterproc(cg, fset, filePath, funcName, inner, state, ctx)...)
			}
		}

	case *ast.DeclStmt:
		if genDecl, ok := s.Decl.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
			for _, spec := range genDecl.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for i, value := range vs.Values {
						chain := selectorChain(value)
						if kind, matched := MatchGoSource(chain); matched {
							if i < len(vs.Names) {
								varName := vs.Names[i].Name
								state.Mark(varName, TaintSource{
									VarName: varName,
									Line:    fset.Position(value.Pos()).Line,
									Kind:    kind,
									Expr:    chain,
								})
							}
						}
					}
				}
			}
		}
	}

	return flows
}

// analyzeGoAssignInterproc extends analyzeGoAssign with cross-function tracking.
func analyzeGoAssignInterproc(cg *CallGraph, fset *token.FileSet, filePath, funcName string, assign *ast.AssignStmt, state *TaintState, ctx *TaintContext) []TaintFlow {
	var flows []TaintFlow

	for i, rhs := range assign.Rhs {
		if i >= len(assign.Lhs) {
			break
		}
		lhsIdent, ok := assign.Lhs[i].(*ast.Ident)
		if !ok {
			continue
		}
		varName := lhsIdent.Name

		chain := selectorChain(rhs)

		if IsGoSanitizer(chain) {
			state.Clear(varName)
			continue
		}

		if kind, matched := MatchGoSource(chain); matched {
			state.Mark(varName, TaintSource{
				VarName: varName,
				Line:    fset.Position(rhs.Pos()).Line,
				Kind:    kind,
				Expr:    chain,
			})
			continue
		}

		rhsIdents := extractIdents(rhs)
		for _, id := range rhsIdents {
			if src, tainted := state.Get(id); tainted {
				state.Mark(varName, TaintSource{
					VarName: varName,
					Line:    fset.Position(rhs.Pos()).Line,
					Kind:    src.Kind,
					Expr:    src.Expr,
				})
				break
			}
		}

		// Check if RHS is a call to a known function with tainted args.
		if call, ok := rhs.(*ast.CallExpr); ok {
			callChain := selectorChain(call.Fun)

			// Check direct sink match.
			if ruleID, cwe, matched := MatchGoSink(callChain); matched {
				argIdents := extractCallArgIdents(call)
				for _, argName := range argIdents {
					if src, tainted := state.Get(argName); tainted {
						flows = append(flows, TaintFlow{
							Source:   src,
							SinkLine: fset.Position(call.Pos()).Line,
							SinkExpr: callChain,
							RuleID:   ruleID,
							CWE:      cwe,
							FilePath: filePath,
							FuncName: funcName,
							Language: "go",
						})
					}
				}
			}

			// Follow into called function if in call graph.
			if ctx.CanDescend() {
				calleeName := calleeNameFromExpr(call.Fun)
				if callee, ok := cg.Funcs[calleeName]; ok {
					taintedParams := buildTaintedParamMap(call, state)
					if len(taintedParams) > 0 {
						childCtx := ctx.Push(calleeName)
						childFlows := analyzeGoFuncInterproc(cg, callee, taintedParams, childCtx)

						promoteInterproc(childFlows, funcName)
						flows = append(flows, childFlows...)
					}
				}
			}
		}
	}

	return flows
}

// analyzeGoCallInterproc extends analyzeGoCall with cross-function tracking.
func analyzeGoCallInterproc(cg *CallGraph, fset *token.FileSet, filePath, funcName string, call *ast.CallExpr, state *TaintState, ctx *TaintContext) []TaintFlow {
	chain := selectorChain(call.Fun)

	var flows []TaintFlow

	// Direct sink check.
	if ruleID, cwe, matched := MatchGoSink(chain); matched {
		argIdents := extractCallArgIdents(call)
		for _, argName := range argIdents {
			if src, tainted := state.Get(argName); tainted {
				flows = append(flows, TaintFlow{
					Source:   src,
					SinkLine: fset.Position(call.Pos()).Line,
					SinkExpr: chain,
					RuleID:   ruleID,
					CWE:      cwe,
					FilePath: filePath,
					FuncName: funcName,
					Language: "go",
				})
			}
		}

		// String concatenation in args.
		for _, arg := range call.Args {
			if bin, ok := arg.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
				for _, id := range extractIdents(bin) {
					if src, tainted := state.Get(id); tainted {
						found := false
						for k := range flows {
							if flows[k].Source.VarName == src.VarName {
								found = true
								break
							}
						}
						if !found {
							flows = append(flows, TaintFlow{
								Source:   src,
								SinkLine: fset.Position(call.Pos()).Line,
								SinkExpr: chain,
								RuleID:   ruleID,
								CWE:      cwe,
								FilePath: filePath,
								FuncName: funcName,
								Language: "go",
							})
						}
					}
				}
			}
		}
	}

	// Follow into called function.
	if ctx.CanDescend() {
		calleeName := calleeNameFromExpr(call.Fun)
		if callee, ok := cg.Funcs[calleeName]; ok {
			taintedParams := buildTaintedParamMap(call, state)
			if len(taintedParams) > 0 {
				childCtx := ctx.Push(calleeName)
				childFlows := analyzeGoFuncInterproc(cg, callee, taintedParams, childCtx)

				promoteInterproc(childFlows, funcName)
				flows = append(flows, childFlows...)
			}
		}
	}

	return flows
}

// promoteInterproc re-tags intraprocedural rules to interprocedural equivalents
// and prefixes the function name with the caller chain.
func promoteInterproc(flows []TaintFlow, callerFunc string) {
	for j := range flows {
		flows[j].FuncName = callerFunc + " -> " + flows[j].FuncName
		switch flows[j].RuleID {
		case "TAINT-001":
			flows[j].RuleID = "TAINT-006"
		case "TAINT-002":
			flows[j].RuleID = "TAINT-007"
		}
	}
}

// calleeNameFromExpr extracts the simple function name from a call expression.
func calleeNameFromExpr(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		// For method calls like pkg.Func, return just "Func"
		// since we index functions by name, not fully qualified.
		return e.Sel.Name
	}
	return ""
}

// buildTaintedParamMap creates a mapping from argument index to taint source
// for arguments that are tainted.
func buildTaintedParamMap(call *ast.CallExpr, state *TaintState) map[int]TaintSource {
	params := make(map[int]TaintSource)
	for i, arg := range call.Args {
		for _, id := range extractIdents(arg) {
			if src, tainted := state.Get(id); tainted {
				params[i] = src
				break
			}
		}
	}
	return params
}

// deduplicateFlows removes duplicate flows based on rule ID, file, function, and lines.
func deduplicateFlows(flows []TaintFlow) []TaintFlow {
	type key struct {
		RuleID   string
		FilePath string
		FuncName string
		SrcLine  int
		SinkLine int
	}
	seen := make(map[key]bool)
	var result []TaintFlow
	for i := range flows {
		f := &flows[i]
		k := key{f.RuleID, f.FilePath, f.FuncName, f.Source.Line, f.SinkLine}
		if !seen[k] {
			seen[k] = true
			result = append(result, flows[i])
		}
	}
	return result
}
