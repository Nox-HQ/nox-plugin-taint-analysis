package main

import (
	"regexp"
	"strings"
)

// TextFuncInfo holds information about a function found via regex parsing.
type TextFuncInfo struct {
	Name      string
	Params    []string
	Body      []string // lines of the function body
	FilePath  string
	StartLine int
	Language  string
}

// TextCallGraph indexes functions from Python/JS/TS files for interprocedural analysis.
type TextCallGraph struct {
	Funcs map[string]*TextFuncInfo
}

// NewTextCallGraph creates an empty text call graph.
func NewTextCallGraph() *TextCallGraph {
	return &TextCallGraph{
		Funcs: make(map[string]*TextFuncInfo),
	}
}

// Regex patterns for function definitions and parameter extraction.
var (
	pyFuncDefFull = regexp.MustCompile(`^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)`)
	jsFuncDefFull = regexp.MustCompile(`^\s*(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)`)
	jsArrowFull   = regexp.MustCompile(`^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>`)
	jsMethodFull  = regexp.MustCompile(`^\s*(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{`)
)

// AddPythonFile indexes functions from a Python file.
func (tcg *TextCallGraph) AddPythonFile(filePath, content string) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		m := pyFuncDefFull.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		funcName := m[1]
		params := parseParamList(m[2])
		body := extractPyFuncBody(lines, i)

		tcg.Funcs[funcName] = &TextFuncInfo{
			Name:      funcName,
			Params:    params,
			Body:      body,
			FilePath:  filePath,
			StartLine: i + 1,
			Language:  "python",
		}
	}
}

// AddJSFile indexes functions from a JavaScript/TypeScript file.
func (tcg *TextCallGraph) AddJSFile(filePath, content, lang string) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		var funcName string
		var paramStr string

		if m := jsFuncDefFull.FindStringSubmatch(line); m != nil {
			funcName = m[1]
			paramStr = m[2]
		} else if m := jsArrowFull.FindStringSubmatch(line); m != nil {
			funcName = m[1]
			paramStr = m[2]
		} else if m := jsMethodFull.FindStringSubmatch(line); m != nil {
			funcName = m[1]
			paramStr = m[2]
		} else {
			continue
		}

		params := parseParamList(paramStr)
		body := extractJSFuncBody(lines, i)

		tcg.Funcs[funcName] = &TextFuncInfo{
			Name:      funcName,
			Params:    params,
			Body:      body,
			FilePath:  filePath,
			StartLine: i + 1,
			Language:  lang,
		}
	}
}

// parseParamList splits a parameter string into individual parameter names.
func parseParamList(params string) []string {
	params = strings.TrimSpace(params)
	if params == "" {
		return nil
	}
	parts := strings.Split(params, ",")
	var names []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Strip type annotations: "name: type" → "name", "name=default" → "name"
		if idx := strings.IndexAny(p, ":="); idx > 0 {
			p = strings.TrimSpace(p[:idx])
		}
		// Strip destructuring and rest operators.
		p = strings.TrimLeft(p, ".*")
		if p != "" && p != "self" && p != "cls" {
			names = append(names, p)
		}
	}
	return names
}

// extractPyFuncBody extracts the body lines of a Python function by indentation.
func extractPyFuncBody(lines []string, defLine int) []string {
	indent := len(lines[defLine]) - len(strings.TrimLeft(lines[defLine], " \t"))
	var body []string
	body = append(body, lines[defLine])

	for i := defLine + 1; i < len(lines) && len(body) < 200; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || trimmed[0] == '#' {
			body = append(body, lines[i])
			continue
		}
		lineIndent := len(lines[i]) - len(strings.TrimLeft(lines[i], " \t"))
		if lineIndent <= indent {
			break
		}
		body = append(body, lines[i])
	}
	return body
}

// extractJSFuncBody extracts the body lines of a JS function by brace matching.
func extractJSFuncBody(lines []string, defLine int) []string {
	var body []string
	braceDepth := 0
	started := false

	for i := defLine; i < len(lines) && len(body) < 200; i++ {
		body = append(body, lines[i])
		braceDepth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		if strings.Contains(lines[i], "{") {
			started = true
		}
		if started && braceDepth <= 0 {
			break
		}
	}
	return body
}

// AnalyzeTextFilesInterprocedural performs interprocedural taint analysis on
// Python/JS/TS files by indexing functions and following calls.
func AnalyzeTextFilesInterprocedural(files map[string][]byte, lang string) []TaintFlow {
	tcg := NewTextCallGraph()

	for path, content := range files {
		switch lang {
		case "python":
			tcg.AddPythonFile(path, string(content))
		case "javascript", "typescript":
			tcg.AddJSFile(path, string(content), lang)
		}
	}

	var flows []TaintFlow

	for _, info := range tcg.Funcs {
		ctx := NewTaintContext()
		ctx.Stack = []string{info.Name}
		funcFlows := analyzeTextFuncInterproc(tcg, info, nil, ctx, lang)
		flows = append(flows, funcFlows...)
	}

	return deduplicateFlows(flows)
}

// analyzeTextFuncInterproc runs taint analysis on a text-parsed function body
// and follows calls to other indexed functions.
func analyzeTextFuncInterproc(tcg *TextCallGraph, info *TextFuncInfo, taintedParams map[int]TaintSource, ctx *TaintContext, lang string) []TaintFlow {
	state := NewTaintState()
	var flows []TaintFlow

	// Mark parameters as tainted.
	for idx, src := range taintedParams {
		if idx < len(info.Params) {
			state.Mark(info.Params[idx], src)
		}
	}

	// Walk through each line of the function body.
	for lineIdx, line := range info.Body {
		lineNo := info.StartLine + lineIdx

		// Check for variable assignment.
		var varName, rhsExpr string
		switch lang {
		case "python":
			if m := pyAssign.FindStringSubmatch(line); m != nil {
				varName = m[1]
				rhsExpr = m[2]
			}
		case "javascript", "typescript":
			if m := jsAssignConst.FindStringSubmatch(line); m != nil {
				varName = m[1]
				rhsExpr = m[2]
			} else if m := jsAssignBare.FindStringSubmatch(line); m != nil {
				varName = m[1]
				rhsExpr = m[2]
			}
		}

		if varName != "" {
			if IsTextSanitizer(rhsExpr, lang) {
				state.Clear(varName)
				continue
			}
			if kind, matched := MatchTextSource(rhsExpr, lang); matched {
				state.Mark(varName, TaintSource{
					VarName: varName,
					Line:    lineNo,
					Kind:    kind,
					Expr:    strings.TrimSpace(rhsExpr),
				})
				continue
			}
			for _, tv := range state.TaintedVars() {
				if containsWord(rhsExpr, tv) {
					src, _ := state.Get(tv)
					state.Mark(varName, TaintSource{
						VarName: varName,
						Line:    lineNo,
						Kind:    src.Kind,
						Expr:    src.Expr,
					})
					break
				}
			}

			// Check if RHS contains a call to an indexed function with tainted args.
			if ctx.CanDescend() {
				for calleeName, callee := range tcg.Funcs {
					if strings.Contains(rhsExpr, calleeName+"(") {
						taintedArgs := buildTextTaintedParams(rhsExpr, calleeName, state)
						if len(taintedArgs) > 0 {
							childCtx := ctx.Push(calleeName)
							childFlows := analyzeTextFuncInterproc(tcg, callee, taintedArgs, childCtx, lang)
							promoteInterproc(childFlows, info.Name)
							flows = append(flows, childFlows...)
						}
					}
				}
			}
		}

		// Check if line contains a sink with a tainted variable.
		if ruleID, cwe, matched := MatchTextSink(line, lang); matched {
			for _, tv := range state.TaintedVars() {
				if containsWord(line, tv) {
					src, _ := state.Get(tv)
					flows = append(flows, TaintFlow{
						Source:   src,
						SinkLine: lineNo,
						SinkExpr: strings.TrimSpace(line),
						RuleID:   ruleID,
						CWE:      cwe,
						FilePath: info.FilePath,
						FuncName: info.Name,
						Language: lang,
					})
					break
				}
			}
		}

		// Check for function calls to indexed functions and follow.
		if ctx.CanDescend() {
			for calleeName, callee := range tcg.Funcs {
				if strings.Contains(line, calleeName+"(") && varName == "" {
					taintedArgs := buildTextTaintedParams(line, calleeName, state)
					if len(taintedArgs) > 0 {
						childCtx := ctx.Push(calleeName)
						childFlows := analyzeTextFuncInterproc(tcg, callee, taintedArgs, childCtx, lang)
						promoteInterproc(childFlows, info.Name)
						flows = append(flows, childFlows...)
					}
				}
			}
		}
	}

	return flows
}

// buildTextTaintedParams builds a tainted parameter map for text-based analysis.
func buildTextTaintedParams(line, funcName string, state *TaintState) map[int]TaintSource {
	// Find the argument list in the call.
	idx := strings.Index(line, funcName+"(")
	if idx < 0 {
		return nil
	}
	argStart := idx + len(funcName) + 1
	depth := 1
	argEnd := argStart
	for argEnd < len(line) && depth > 0 {
		switch line[argEnd] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth > 0 {
			argEnd++
		}
	}
	if argEnd > len(line) {
		return nil
	}

	argStr := line[argStart:argEnd]
	args := strings.Split(argStr, ",")

	params := make(map[int]TaintSource)
	for i, arg := range args {
		arg = strings.TrimSpace(arg)
		for _, tv := range state.TaintedVars() {
			if containsWord(arg, tv) {
				src, _ := state.Get(tv)
				params[i] = src
				break
			}
		}
	}
	return params
}
