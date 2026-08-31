---
name: cognium-attack-surface
description: Summarize this workspace's attack surface with Cognium MCP (entry points, reachable sinks, taint paths).
---

# Attack surface summary

Map the workspace with the `cognium` MCP tools. Stay defensive: describe entry points and confirmed flows. Do not provide exploit steps, payloads, or attack procedures.

1. Resolve the workspace root as an **absolute** path. If no scan is cached, call `scan` on that path first.
2. Call `attack_surface_summary` with `project_root` set to the workspace root.
3. Call `list_entry_points` for attacker-reachable handlers (routes, middleware, listeners).
4. Call `list_reachable_sinks` for sinks that have a real taint flow (optionally filter by `sink_type`).
5. Call `taint_paths` for cross-file flows. Filter with `sink_type` when the user named a class (SQLi, XSS, command injection, path traversal).

Report:

- Entry points by framework / language
- Reachable sinks by type (not lexical-only matches)
- Cross-file taint path counts and the hottest files
- Highest-severity confirmed flows, with finding ids for follow-up `explain_finding`

If the user wants a fix, follow with `explain_finding` → `check_sanitizer` before editing.
