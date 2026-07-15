# Changelog

All notable changes to `@cognium/mcp-server` are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
