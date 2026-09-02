> ## ⚠️ Archived — superseded by nox core
>
> **This plugin is retired. Do not install it.** Remove it with
> `nox plugin remove nox/taint-analysis`; nox core needs no configuration to
> replace it.
>
> Core's taint engine has overtaken this plugin and now exceeds it. As of
> **nox 1.33.0** the plugin no longer adds a single finding core does not
> already make, and it re-introduces false positives core has fixed.
>
> Measured on the four precision suites (base, Clojure, PHP, Ruby — 53
> ground-truth `nox-expect` TAINT expectations), with the plugin at its final
> version 0.7.3:
>
> | | TP | FP | FN | precision | recall |
> |---|---|---|---|---|---|
> | nox 1.33.0 core only | 53 | 0 | 0 | **1.000** | 1.000 |
> | core + this plugin | 53 | **8** | 0 | **0.869** | 1.000 |
>
> Zero true positives added. Eight false positives, which are precisely the
> cases core fixed in 1.33.0: a sanitizer applied on the binding line
> (`clean_inline_sanitizer.py`), the argument-vector exemption for a command
> invoked without a shell (`clean_argv_exec.py`), a parameterised query
> (`clean_safe_db.py`), and three cross-class XSS reports on Go
> command-injection and path-traversal fixtures.
>
> That is the ordinary fate of a plugin that reimplements a core analyzer: it
> holds still while core improves, and the drift surfaces as false positives
> rather than as an error. Core taint now resolves imports and aliases across
> Python, JS/TS, Clojure, Elixir and C#, reads Go composite literals, and
> honours same-statement sanitizers — none of which this plugin knows about.
>
> Nothing is lost by removing it: recall was identical at 1.000 in both arms.

# nox-plugin-taint-analysis

Intraprocedural taint analysis plugin for [Nox](https://github.com/nox-hq/nox). Tracks data flow from untrusted sources (HTTP parameters, environment variables, CLI arguments) to dangerous sinks (SQL queries, shell commands, HTML output) within function bodies.

## Rules

| ID | Description | Severity | CWE |
|---|---|---|---|
| TAINT-001 | SQL Injection: tainted input flows to SQL execution | High | CWE-89 |
| TAINT-002 | Command Injection: tainted input flows to shell execution | Critical | CWE-78 |
| TAINT-003 | XSS: tainted input flows to HTML output | High | CWE-79 |
| TAINT-004 | Path Traversal: tainted input flows to file operations | High | CWE-22 |
| TAINT-005 | Code Injection: tainted input flows to eval/deserialization | High | CWE-94 |

## Supported Languages

- **Go**: AST-based analysis using `go/ast` and `go/parser`
- **Python**: Regex-based with variable tracking
- **JavaScript/TypeScript**: Regex-based with variable tracking

## Build

```bash
make build
make test
make lint
```

## License

Apache-2.0
