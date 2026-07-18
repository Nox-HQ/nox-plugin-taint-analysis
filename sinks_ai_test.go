package main

import "testing"

// AI sinks ported from the nox in-tree copy of this plugin. The tests there
// targeted classifyInterprocSink, which does not exist in this implementation,
// so they are rewritten against the public MatchGoSink / MatchTextSink API.
func TestMatchGoSink_AIPromptAndEmbedding(t *testing.T) {
	cases := []struct {
		chain, rule, cwe string
	}{
		{"client.CreateChatCompletion", "TAINT-AI-001", "CWE-77"},
		{"c.Messages.New", "TAINT-AI-001", "CWE-77"},
		{"model.GenerateContent", "TAINT-AI-001", "CWE-77"},
		{"client.CreateEmbeddings", "TAINT-AI-002", "CWE-200"},
		{"openai.Tool", "TAINT-AI-003", "CWE-77"},
	}
	for _, c := range cases {
		rule, cwe, ok := MatchGoSink(c.chain)
		if !ok || rule != c.rule || cwe != c.cwe {
			t.Errorf("MatchGoSink(%q) = (%q,%q,%v), want (%q,%q,true)",
				c.chain, rule, cwe, ok, c.rule, c.cwe)
		}
	}
}

func TestMatchTextSink_AIPythonAndJS(t *testing.T) {
	cases := []struct{ line, lang, rule string }{
		{"resp = client.chat.completions.create(model=m)", "python", "TAINT-AI-001"},
		{"r = litellm.completion(messages=msgs)", "python", "TAINT-AI-001"},
		{"e = client.embeddings.create(input=text)", "python", "TAINT-AI-002"},
		{"const r = await openai.chat.completions.create({})", "javascript", "TAINT-AI-001"},
		{"const e = await client.embeddings.create({})", "javascript", "TAINT-AI-002"},
	}
	for _, c := range cases {
		rule, _, ok := MatchTextSink(c.line, c.lang)
		if !ok || rule != c.rule {
			t.Errorf("MatchTextSink(%q, %s) = (%q,%v), want (%q,true)", c.line, c.lang, rule, ok, c.rule)
		}
	}
}

// Guards the deliberate exclusion this port preserved. The nox in-tree copy had
// re-added fmt.Fprintf as a TAINT-003 (XSS) sink; it was removed here on
// purpose because the selector matcher cannot tell whether the writer is an
// http.ResponseWriter, so every CLI print and log line became an XSS finding.
// Re-adding it would be a false-positive regression, not a coverage gain.
func TestMatchGoSink_FmtFprintfIsNotAnXSSSink(t *testing.T) {
	if _, _, ok := MatchGoSink("fmt.Fprintf"); ok {
		t.Fatal("fmt.Fprintf must not be an XSS sink — it is general formatted output " +
			"(stdout, logs, buffers) and flagging it produced overwhelming false positives")
	}
	// The genuine HTML-rendering sinks must still match.
	for _, chain := range []string{"template.HTML", "w.Write"} {
		if _, _, ok := MatchGoSink(chain); !ok {
			t.Errorf("%q should still be a TAINT-003 sink", chain)
		}
	}
}

// Pre-existing rules must be unaffected by the AI additions.
func TestMatchGoSink_OriginalRulesPreserved(t *testing.T) {
	for _, c := range []struct{ chain, rule string }{
		{"db.Query", "TAINT-001"},
		{"exec.Command", "TAINT-002"},
		{"os.ReadFile", "TAINT-004"},
	} {
		if rule, _, ok := MatchGoSink(c.chain); !ok || rule != c.rule {
			t.Errorf("MatchGoSink(%q) = (%q,%v), want (%q,true)", c.chain, rule, ok, c.rule)
		}
	}
}

// The false-positive guard that matters. AI sinks are TAINT sinks, so they must
// only fire when attacker-controlled data actually reaches the model call. A
// hardcoded prompt is the overwhelmingly common case in real code, and flagging
// it would reproduce the fmt.Fprintf problem at a larger scale.
func TestAISinks_UntaintedPromptDoesNotFire(t *testing.T) {
	untainted := []byte(`package main

func ask(client *OpenAIClient) {
	// Prompt is a literal — nothing attacker-controlled reaches the model.
	client.CreateChatCompletion("summarise the changelog")
}
`)
	for _, f := range AnalyzeGoFileInterprocedural(map[string][]byte{"ai.go": untainted}) {
		if len(f.RuleID) >= 9 && f.RuleID[:9] == "TAINT-AI-" {
			t.Errorf("untainted AI call produced %s — sinks must be taint-gated", f.RuleID)
		}
	}
}

// The true positive it exists for: request data reaching a completion.
func TestAISinks_TaintedPromptIsReported(t *testing.T) {
	handler := []byte(`package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	sendPrompt(q)
}
`)
	sender := []byte(`package main

func sendPrompt(data string) {
	client.CreateChatCompletion(data)
}
`)
	var found bool
	for _, f := range AnalyzeGoFileInterprocedural(map[string][]byte{"h.go": handler, "s.go": sender}) {
		if f.RuleID == "TAINT-AI-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("request data reaching CreateChatCompletion across files should report TAINT-AI-001")
	}
}
