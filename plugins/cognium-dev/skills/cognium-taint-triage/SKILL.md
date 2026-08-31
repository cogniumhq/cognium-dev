---
name: cognium-taint-triage
description: Triage Cognium taint paths and attack surface, then propose a sanitizer-backed defensive fix. Use when explaining a finding, tracing source-to-sink flow, checking sanitizers, or remediating SQLi, XSS, command injection, path traversal, or SSRF.
---

# Cognium taint triage and defensive fix

Triage with the `cognium` MCP tools, then propose a **defensive** fix grounded in circle-ir's sanitizer catalog. Do not invent flows, do not claim a helper is a sanitizer unless `check_sanitizer` says so, and do not include exploit steps, payloads, or attack procedures.

## When to use

- The user asks why a finding matters, where taint flows, or how to fix it.
- A scan already ran and the next step is triage or remediation.
- The user wants an attack-surface overview (entry points, reachable sinks).

## Tool-call flow

Assume a prior `scan` of the project root. If the cache is empty, call `scan` first with an **absolute** `path`.

1. `attack_surface_summary` (`project_root`) — entry points, sinks, cross-file taint paths, hottest files.
2. `taint_paths` — filter with `sink_type`, `source_file`, or `sink_file` when focusing on one issue. Types include `sql_injection`, `xss`, `command_injection`, `path_traversal`.
3. `list_reachable_sinks` — sinks that have a real taint flow (not lexical-only matches). Prefer this list when deciding what to fix.
4. `list_entry_points` — attacker-reachable handlers (HTTP routes, middleware, listeners), grouped by framework.
5. `explain_finding` — CWE metadata, remediation text, and suggested sanitizers for one `finding_id`.
6. `describe_sink` / `describe_source` — canonical sink or source category (CWE, remediation, catalog patterns).
7. `find_similar` — other findings with the same `rule_id` and/or sink type.
8. **Before proposing a fix**, `check_sanitizer` with:
   - `function_qualified_name` (for example `DOMPurify.sanitize` or `org.owasp.esapi.Encoder.encodeForHTML`)
   - `sink_type` matching the finding
   - optional `language`

If `check_sanitizer` returns `isValidSanitizer: false`, do not claim the wrapper sanitizes that sink. Use `alternatives` from the tool, or `describe_sink` for cataloged sanitizers.

## How to propose a fix

- Prefer the engine's `remediation` / `fix` fields from `explain_finding`.
- Name the sanitizer or parameterized API the catalog recognizes for that sink type and language.
- Keep the change small: validate or encode at the sink, or use a safe API (parameterized queries, framework HTML encoding, allowlisted path join).
- After editing, call `refresh` then `scan` on the same absolute project root and confirm the finding is gone or the flow is sanitized.
- If similar findings exist, list them and offer to apply the same defensive pattern.

## Do not

- Provide exploit payloads, proof-of-concept attacks, or bypass recipes.
- Guess that a helper is a sanitizer without `check_sanitizer`.
- Treat a lexical sink hit with empty `taint.flows` as a confirmed flow. Say when the engine did not confirm reachability.
