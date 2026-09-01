---
name: cognium-scan
description: Run Cognium SAST on the workspace root via MCP and report the highest-severity findings.
---

# Scan this workspace with Cognium

Run a deterministic SAST scan with the `cognium` MCP server. Do not guess findings. Do not include exploit steps, payloads, or attack procedures.

1. Resolve the workspace root as an **absolute** path.
2. Call `scan` with `path` set to that root. Add `forceRefresh: true` if a previous scan in this session may be stale.
3. Call `attack_surface_summary` with the same `project_root`.
4. For the highest-severity **security** findings, call `explain_finding` (`project_root` + finding `id`).
5. Call `find_similar` on those ids so repeated `rule_id` / sink patterns are listed.

Report:

- Finding counts by severity and category
- Top security findings with `id`, `rule_id`, CWE, file, line, and engine message
- Whether each item has a confirmed taint flow versus a lexical sink only
- A short defensive next step (triage with `/cognium-attack-surface` or a sanitizer-backed fix), not an exploit
