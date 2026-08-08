# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- chore(deps): Go 1.26.5 and nox SDK v1.17.0 (#30)
- chore(security): nox remediation (deps + actions) (#29)
- ci: add nox-remediate caller (deps + action-pin remediation)
- ci: point the registry notice at where entries actually go (#28)
- ci: add nox self-scan and changed-files PR gate (#27)


## [Unreleased]

## [v0.7.3] - 2026-08-08

### Fixed

- Taint fingerprints no longer depend on the directory the scan ran in (#31)

  `reportPath` makes finding locations workspace-relative before they reach
  `fingerprint()`. Previously the walk handed absolute paths through, so the
  same finding on the same commit hashed differently in a CI checkout, a
  developer clone and a git worktree:

      local checkout  f2fc80a3...
      git worktree    6a6e14b1...
      CI runner       2ec40d1d...

  A baseline entry was therefore only valid on the machine that produced it:
  `nox baseline add` locally left CI reporting the same reviewed finding as
  net-new, and the gate failed. Consumers had to exclude whole files to work
  around it.

  The fix landed 41 minutes after the v0.7.2 tag and has been unreleased since
  2026-07-25, so every install until now carried the old behaviour.

### Changed

- nox SDK 1.17.0 -> 1.24.0, nox action 1.19.0 -> 1.24.0, actions/setup-go 6.5.0 -> 7.0.0
- Dependency and action-pin remediation (#33, #36)


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
