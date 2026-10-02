# Changelog

All notable changes to Caveat are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] — 2026-10-02

First release.

### The reader
- **Tolerant splitter** — a command line is read once into labelled chunks
  (word, quoted run, substitution, redirection, operator) and then grouped into
  stages. Handles pipes, `&&`, `||`, `;`, newlines, backgrounding, subshells,
  redirections including `2>&1` and `>&`, here-documents, and quoting that never
  closes. It reads *into* a line as well as across it: `$( … )`, backticks,
  `<( … )` and a `-c` script handed to a shell become stages of their own, down
  three levels.
- **Pipeline diagram** — the signature element. One box per stage, left to
  right, wrapping like text; the command in mono, its role beneath, the operator
  between boxes labelled with what travels down it, a `ROOT` mark on any stage
  that runs elevated, and the alert treatment on a stage executing input that
  nothing has read.
- **Dictionary** — 187 commands with a one-line plain-English role, a family the
  rules reason over structurally, and a glossary for the flags that change what
  a command does to your machine. Clustered short options expand (`-fsSL` →
  four flags) while single-dash long options stay whole (`find -name`).
- **27 rules** — running unread code, recursive deletes and their targets, raw
  writes to a disk, the fork bomb, permissions and setuid, elevation and pipes
  into `sudo`, disabled certificate and host-key checking, reverse shells,
  covering tracks, persistence, firewalls and mandatory access control,
  container boundaries, package provenance, unquoted expansions, and everything
  Caveat could not read. Every finding above NOTICE carries a safer alternative.
- **Verdict** — ROUTINE / WORTH A LOOK / RISKY / DESTRUCTIVE, with an honesty
  ceiling: a line containing an unrecognised command, unclosed quoting or a
  command word built from a variable can never be ROUTINE, and the headline says
  which of those capped it. The word "safe" never appears in a result.

### Interfaces
- A PyQt6 window in the house style — warm paper and gold, true-black dark mode,
  and an Auto theme that follows the OS.
- A dependency-free command line sharing the same engine, with text and `--json`
  output, a `-e` flag for reading a line directly, and standard-input support.

### Engineering
- The engine (`caveat.core`) is pure standard library — no third-party
  dependencies, no network, no sockets, and no code path that executes the input.
- 865 tests across the splitter, the dictionary, every rule (each with a line
  that must trip it and a line that must not), the verdict and its ceiling, the
  CLI contract, the diagram's wrapping arithmetic, and a WCAG-AA contrast suite
  covering every text/background pairing in both themes.
- Off-screen screenshot capture and a repository-art generator whose social card
  is held inside GitHub's safe border by a registered-rectangle check and a
  measurement of the rendered pixels.
