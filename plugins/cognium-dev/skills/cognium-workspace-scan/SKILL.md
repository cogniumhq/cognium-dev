---
name: cognium-workspace-scan
description: Run Cognium SAST on the workspace with the cognium MCP tools and report findings. Use when the user asks to scan, audit, or check the project for vulnerabilities, taint issues, CWEs, or SAST results.
---

# Cognium workspace scan

Run **deterministic** SAST through the `cognium` MCP server (`@cognium/mcp-server`). Findings come from circle-ir. Do not invent vulnerabilities, do not estimate severity, and do not describe exploit steps, payloads, or attack procedures.

## When to use

- The user asks to scan the workspace, a directory, or a file.
- A security review needs engine-backed evidence rather than guessed findings.
- After a large change, when the user wants an updated SAST report.

## Prerequisites

- The `cognium` MCP server from this plugin is enabled (stdio, `npx -y @cognium/mcp-server`).
- Node.js **≥ 20.19.0** is on the PATH so `npx` can start the server.
- No API keys or plugin variables are required.

## Tool-call flow

1. Resolve the scan target as an **absolute path**. Default to the workspace root. `scan.path` must be absolute.
2. Call `scan` on that path. Optional filters:
   - `language`: `java` | `javascript` | `typescript` | `python` | `go` | `rust` | `bash` | `html`
   - `severity`: `critical` | `high` | `medium` | `low`
   - `categories`: `security` | `reliability` | `performance` | `maintainability` | `architecture`
   - `forceRefresh`: `true` after git checkout or when results look stale
3. Call `attack_surface_summary` with the same `project_root` for a posture roll-up (entry points × sinks × cross-file taint paths, top files).
4. For the highest-severity security findings, call `explain_finding` with `project_root` and the finding `id` from `scan`.
5. Call `find_similar` on those ids so the same `rule_id` / sink type is not missed elsewhere.

If the cache is stale or a prior scan used different options, call `refresh` then `scan` again.

## How to report

- Lead with counts by severity, then the highest-severity security findings.
- For each finding cite `id`, `rule_id`, CWE, file, line, and the engine message. Prefer `explain_finding` text over paraphrasing.
- Distinguish **confirmed taint flows** (paths / reachable sinks) from lexical sink mentions.
- If `scan` fails (server not running, Node too old, path missing), say so and stop. Do not fill in guessed findings.
- Stay defensive: describe the issue and point to remediation from the engine. Never provide exploit steps, payloads, or proof-of-concept attacks.

## Languages

Production support: Java, JavaScript, TypeScript, Python, Go, Rust, Bash, HTML.
