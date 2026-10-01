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

The same stdio config is bundled in the [Cognium SAST plugin](../../plugins/cognium-dev) for Cursor (`mcp.json`) and Claude Code (`.mcp.json`). That plugin also ships skills, rules, commands, and a SAST reviewer agent.

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

## Using it as a library

The package is side-effect free to import: nothing is built, read or connected
until you ask for it. The stdio binary is a separate file, so mounting the
server over your own transport does not spawn a subprocess.

```ts
import { createServer } from '@cognium/mcp-server';

// Floor plus whatever optional modules this install has.
const { server, discovery } = await createServer();
console.error(discovery.enablement.state); // 'floor' | 'extended' | 'commercial'
await server.connect(myTransport);
```

`buildServer(options)` is the synchronous form: it registers exactly what you
pass and resolves nothing.

## Optional tool modules

The eleven tools above are always present. A separate package may add more by
exporting a `ToolModule`:

```ts
export default {
  id: 'example/mcp',
  version: '1.0.0',
  licence: 'MIT',
  circleIrRange: '4.9',           // the circle-ir major.minor it was built against
  register(server, ctx) {
    // ctx.cache      — the server's analysis cache, shared with every tool
    // ctx.enablement — what this install may offer; the module decides what
    //                  to register, and checks again at call time
  },
};
```

Set `COGNIUM_MCP_MODULES` to a comma-separated list of specifiers to control
what is looked for, or to `none` to look for nothing.

**The server comes up either way.** A module that is absent, broken, wrongly
shaped or built against a different `circle-ir` minor is refused on one line of
stderr, and the eleven built-in tools serve as normal.

| Variable | Effect |
|---|---|
| `COGNIUM_MCP_MODULES` | Which module specifiers to look for. `none` disables. |
| `COGNIUM_ENDPOINT` | An opaque endpoint passed through to modules. The server never parses or connects to it. |
| `COGNIUM_LICENSE` | A licence token, verified offline. Also read from `$COGNIUM_CONFIG_DIR/license`, default `~/.cognium/license`. |
| `COGNIUM_LICENSE_PUBKEY` | Extra verification keys as `kid=key[,kid=key]`, base64url raw Ed25519, merged over the published ones. A bare key with no `kid=` matches any token, which is a development convenience and not for production. |

A token is `cognium-lic-v1.<base64url payload>.<base64url Ed25519 signature>`.
The payload is `{ kid, org, tier, iat, expiry, entitlements? }` and the
signature covers its **canonical** form (RFC 8785), so a token survives being
re-encoded in transit. `kid` names the signing key, so keys rotate without
invalidating tokens already issued: a verifier holds the old key as long as
tokens signed by it are still in date. An `expiry` given as a bare date is good
through the whole of that UTC day. A field the verifier does not know is still
covered by the signature; a known field of the wrong shape is `malformed`.

Verification is offline — a published key, no network, nothing cached or
written. No key is baked in yet, so tokens currently report `no-key`.

No telemetry, no phone-home, and no feature is locked behind a token: the state
decides what is *listed*, and the terms carry the grant.

## Development

```bash
npm run build       # tsc + chmod +x dist/bin.js
npm run typecheck   # tsc --noEmit
npm test            # vitest run (unit, three-state matrix, stdio smoke)
```

## License

MIT
