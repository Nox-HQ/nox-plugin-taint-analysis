# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.7.0] - 2026-07-18

### Added

- AI taint sinks (TAINT-AI-001..003) for prompt injection, embedding exposure and tool-call arguments

  Reconciles work that had accumulated only in nox's `plugins/` directory,
  where a duplicate copy of this plugin lived. That copy has now been removed;
  this repository is the single source.


### Added

- Initial intraprocedural taint analysis plugin
- Go AST-based analysis using go/ast and go/parser
- Regex-based analysis for Python, JavaScript, and TypeScript
- 5 taint flow rules: SQL injection, command injection, XSS, path traversal, code injection
- Sanitizer detection to reduce false positives
- Multi-line source-to-sink tracking within function bodies
