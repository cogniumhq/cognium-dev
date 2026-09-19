# Changelog

All notable changes to `@cognium/mcp-server` are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.12] - 2026-09-19

### Changed
- Adopts `circle-ir@4.9.20`. No MCP tool, schema, or response-shape changes.

### Consumer Impact

Inherits the Java false-positive removal in `circle-ir@4.9.20`: `File`/`Path`
path projections are no longer taint sources, so agents rescanning a
previously-scanned Java project will see fewer `path_traversal` findings. This
is FP removal with detection on genuinely tainted paths unchanged, not lost
coverage. A stored baseline keyed on finding counts should be re-taken.

## [0.1.11] - 2026-09-19

### Changed
- Adopts `circle-ir@4.9.19`. No MCP tool, schema, or response-shape changes.

### Consumer Impact

Inherits the Java false-positive removal in `circle-ir@4.9.19`: `System.out` /
`System.err` prints are no longer reported as XSS (#387). Agents rescanning a
previously-scanned Java project will see fewer findings — this is FP removal with zero
measured true-positive loss, not lost detection. A stored baseline keyed on finding
counts should be re-taken.

## [0.1.10] - 2026-09-19

### Changed
- Adopts `circle-ir@4.9.17`. No MCP tool, schema, or response-shape changes.

### Consumer Impact

Inherits the additive detection changes in `circle-ir@4.9.17`: new `path_traversal` (CWE-22)
findings on Go code (#374) and new `xss` flows on Python return-value sinks (#368). Agents
rescanning a previously-scanned Go or Python project will see new findings that are not a
regression.

## [0.1.9] - 2026-09-18

### Changed
- Adopts `circle-ir@4.9.16`. No MCP tool, schema, or response-shape changes.

### Consumer Impact

Inherits the new `trust_boundary` (CWE-501) findings from `circle-ir@4.9.16` on Python code
writing untrusted data into a Flask session (#363). Purely additive — 17 findings added on
OWASP BenchmarkPython, all on genuinely vulnerable files, none removed.

## [0.1.8] - 2026-09-18

### Changed
- Adopts `circle-ir@4.9.15`. No MCP tool, schema, or response-shape changes.

### Consumer Impact

Inherits the finding-count changes in `circle-ir@4.9.15`, which move in **both** directions:
fewer `code_injection` / `xss` / `sql_injection` from three JS/TS sink-shape
misclassifications (#358), and **new** C# CWE-502 findings where a `using` declaration now
binds a taint source (#359). A rescan against an existing baseline will show movement that
is not a regression; see the `circle-ir` changelog for the measured numbers.

## [0.1.7] - 2026-09-14

### Changed
- Adopts `circle-ir@4.9.14`. No MCP tool, schema, or response-shape changes.

### Consumer Impact

Inherits the finding-count changes in `circle-ir@4.9.14`, which move in **both**
directions — new CWE-78 on `ProcessBuilder` shell wrappers (#351), a CWE-668 becoming a
CWE-89 on try-with-resources JDBC (#350), and fewer `xss` / `log_injection` findings where
a source variable's name merely appeared inside a string literal at the sink (#353), plus
fewer `plugin_param` sources from never-written map keys (#346). A rescan against an
existing baseline will show movement that is not a regression; see the `circle-ir`
changelog for the measured numbers.

## [0.1.6] - 2026-09-11

### Changed
- Adopts `circle-ir@4.9.13`. No MCP tool, schema, or response-shape changes.

### Consumer Impact
- **Finding counts move in both directions.** Tool responses gain `blocking-main-thread` rows for inline Express/Koa route handlers and `path_traversal` rows where a containment guard falls through without rejecting; they lose C# `path_traversal` (canonicalize-then-contain), C# `ssrf` (constant `BaseAddress` with a relative path), Java/Python `log_injection` (CRLF strip in a helper) and C# `ldap_injection` / `xpath_injection` / `command_injection` / `sql_injection` where an allowlist character strip is applied (circle-ir #272, which merged after the release tag was cut but is present in the published `circle-ir@4.9.13`). Severity tiers are unchanged this release.

## [0.1.5] - 2026-09-10

### Changed
- Adopts `circle-ir@4.9.12`. No MCP tool, schema, or response-shape changes.

### Consumer Impact
- **Severities move upward.** circle-ir #281 threads finding confidence into the severity rules; the `xss`, `path_traversal`, `xxe`, `ssrf`, `ldap_injection` and `xpath_injection` families could not previously be rated above `medium`. Tool responses will carry more `high` severities for identical code. Nothing is added, removed, or lowered.

## [0.1.4] - 2026-09-10

### Changed
- Adopts `circle-ir@4.9.11`, which carries five taint-precision fixes: C# object-carried SQL no longer reports one vulnerability three times, derived taint aliases no longer leak across methods, C# sibling parameters on a signature line are no longer co-tainted, `RegExp.prototype.exec` no longer matches the command-injection sink, and Python `re.compile` no longer matches the code-injection sink. No MCP tool, schema, or response-shape changes.

## [0.1.3] - 2026-09-02

### Changed

- Bump the `circle-ir` dependency to `4.9.10`, which drops the Rust `format!`
  format_string false positive (#294 part 1) and fixes the http_param/http_query
  → xxe finding-reach-map false negative (#282).

## [0.1.2] - 2026-08-31

### Added

- Record the MIT `LICENSE` in the repository package directory and bump the
  version to match the published `latest` tag. Every published tarball
  (`0.1.0`, `0.1.1`, `0.1.2`) already includes the license text; `0.1.1` was
  an intermediate republish left over from an interrupted publish, and `0.1.2`
  is the current `latest`.

## [0.1.0] - 2026-07-15

### Added

- Initial MVP of the Model Context Protocol server for circle-ir.
- Stdio transport (default) for Claude Desktop / Claude Code / Cursor.
- `ProjectCache` with mtime-based invalidation and LRU eviction (cap 3
  concurrent project analyses).
- 11 tools exposing SAST capabilities to LLM clients:
  - `scan` — run full circle-ir analysis on a file or directory.
  - `explain_finding` — CWE metadata + remediation guidance for a single
    finding.
  - `taint_paths` — list cross-file taint flows with optional filters.
  - `list_entry_points` — enumerate Tier-1 attacker-reachable methods.
  - `check_sanitizer` — verify a function is a known sanitizer for a
    sink type.
  - `describe_sink` — metadata about a sink category (CWE, severity,
    remediation).
  - `describe_source` — metadata about a taint source category.
  - `attack_surface_summary` — one-shot codebase attack-surface report.
  - `list_reachable_sinks` — BFS from an entry point to reachable sinks.
  - `find_similar` — cluster findings by shape for bulk triage.
  - `refresh` — invalidate the cache for specific files or the entire
    project.
- 5 read-only resources:
  - `cognium://sast-finding-schema`
  - `cognium://sink-catalog`
  - `cognium://source-catalog`
  - `cognium://sanitizer-catalog`
  - `cognium://passes`
- Size-bounded serialization (findings capped at 500 per response,
  string fields truncated at 2 KB, IR graphs omitted).
- No changes to circle-ir engine — MCP is a strictly additive wrapper.
