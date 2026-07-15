# @cognium/mcp-server

Model Context Protocol (MCP) server exposing the [circle-ir](https://www.npmjs.com/package/circle-ir) SAST engine as a set of structured tools and reference resources for LLM agents (Claude Desktop, Claude Code, Cursor, cognium-ai).

Ships every deterministic capability of circle-ir — polyglot taint analysis, cross-file taint paths, entry-point enumeration, CWE metadata, sanitizer lookups — as MCP tool calls that an LLM can chain without ever guessing at the SAST engine's internal state.

- **Zero LLM in the analysis path.** Every finding this server returns comes from the deterministic circle-ir pipeline. LLM-side reasoning is fed by these tools; it does not decide them.
- **Cache-first.** The server holds up to 3 recent project analyses in memory, keyed by option-set and invalidated by file `mtime`. Repeated tool calls on the same project are effectively free.
- **Size-bounded output.** Findings, taint paths, and snippets are truncated at safe defaults so a single tool call cannot blow past a client context window.

## Install

```bash
npm install -g @cognium/mcp-server
```

Or run in-place from this monorepo:

```bash
cd packages/mcp-server
npm run build
node dist/index.js
```

## Client configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cognium": {
      "command": "npx",
      "args": ["-y", "@cognium/mcp-server"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add cognium -- npx -y @cognium/mcp-server
```

### Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "cognium": {
      "command": "npx",
      "args": ["-y", "@cognium/mcp-server"]
    }
  }
}
```

## Tools

| Tool | Purpose |
| ---- | ------- |
| `scan` | Run the full polyglot SAST pipeline on a file or directory. Returns SastFindings + per-file taint flows + cross-file taint paths. |
| `explain_finding` | Enrich a single finding id with CWE metadata, remediation, CVSS-like score, and sanitizer suggestions. |
| `taint_paths` | List cross-file taint flows filtered by source file, sink file, or sink type. |
| `list_entry_points` | Enumerate every attacker-reachable handler (HTTP routes, middlewares, event listeners) grouped by framework. |
| `list_reachable_sinks` | List every sink of a given category that has a real taint flow reaching it (excludes lexical-only matches). |
| `attack_surface_summary` | Roll-up: entry points × sinks × cross-file taint paths + top files by finding count. |
| `check_sanitizer` | Deterministic yes/no on whether a function is a recognized sanitizer for a sink category. |
| `describe_sink` | CWE, remediation, CVSS-like severity, and sanitizer list for a sink category. |
| `describe_source` | Every framework API pattern circle-ir treats as a source of a given category. |
| `find_similar` | Given a finding id, return other findings sharing the same `rule_id` and/or `sink_type`. |
| `refresh` | Manually invalidate the cache for one project or every project. |

## Resources

| URI | Content |
| --- | ------- |
| `cognium://sast-finding-schema` | JSON Schema for `SastFinding` |
| `cognium://sink-catalog` | Every taint sink pattern known to circle-ir |
| `cognium://source-catalog` | Every taint source pattern |
| `cognium://sanitizer-catalog` | Every sanitizer entry, indexed by sink type |
| `cognium://passes` | Contents of circle-ir `docs/PASSES.md` — canonical pass registry |

## Suggested tool-call flow

1. `scan` on the project root to prime the cache and get a summary.
2. `attack_surface_summary` for a security-posture overview.
3. Iterate over the highest-severity findings with `explain_finding` for CWE context.
4. `find_similar` to catch the same pattern elsewhere.
5. Before proposing a fix, `check_sanitizer` any proposed wrapper against the target sink type.

## Development

```bash
npm run build       # tsc + chmod +x dist/index.js
npm run typecheck   # tsc --noEmit
npm test            # vitest run (unit + smoke)
```

## License

MIT
