# Cognium SAST plugin

MIT-licensed plugin for **cognium-dev**, the OSS SAST scanner from [Cognium Labs](https://cognium.dev). After install, the model can run deterministic taint analysis through [`@cognium/mcp-server`](https://www.npmjs.com/package/@cognium/mcp-server), explain findings, and propose sanitizer-backed **defensive** fixes.

This package is **authored** in this monorepo. It is **not** listed on Cursor Marketplace, Claude’s community directory, or OpenAI’s plugin directory until someone submits it.

- Homepage: https://cognium.dev
- Repository: https://github.com/cogniumhq/cognium-dev
- License: **MIT** (free, public-repo-friendly; not GPL)
- Identifier: `cognium-dev` (v0.1.0)
- Logotype (1:1 SVG, solid `#0B1220` plate): [`assets/logo.svg`](./assets/logo.svg)

After this lands on `main`, the raw GitHub URL for marketplace forms is:

```
https://raw.githubusercontent.com/cogniumhq/cognium-dev/main/plugins/cognium-dev/assets/logo.svg
```

That URL 404s until the plugin is merged to `main`.

## What you get

| Component | Name | Role |
| --------- | ---- | ---- |
| MCP | `cognium` | Stdio server: `npx -y @cognium/mcp-server` (no API keys) |
| Skills | `cognium-workspace-scan`, `cognium-taint-triage` | Scan + report; triage taint paths and propose a sanitizer-backed fix |
| Rules | `prefer-cognium-sast`, `defensive-remediation` | Prefer engine tools over guessed vulns; verify sanitizers before patching (Cursor) |
| Commands | `/cognium-scan`, `/cognium-attack-surface` | Scan the project; summarize entry points, reachable sinks, and taint paths |
| Agent | `cognium-sast-reviewer` | Security review that calls MCP tools instead of free-styling advice |

Suggested tool-call flow (same as the MCP README):

1. `scan` the project root (absolute path)
2. `attack_surface_summary`
3. `explain_finding` on the highest-severity findings
4. `find_similar`
5. `check_sanitizer` before proposing a fix

Languages: Java, JavaScript, TypeScript, Python, Go, Rust, Bash, HTML.

This is a **defensive** SAST plugin. Skills, rules, agents, and commands help you scan, explain, triage, and remediate. They do not include exploit steps, payloads, or attack procedures.

Cursor and Claude Code both start the **stdio** MCP server. OpenAI ChatGPT does not accept local stdio; see [openai/README.md](./openai/README.md).

## Requirements

- **Node.js ≥ 20.19.0** on the PATH (the MCP server is started with `npx`)
- Network access to npm the first time `npx` fetches `@cognium/mcp-server`
- No secrets, tokens, or plugin variables

## MCP files (Cursor vs Claude)

The same stdio command is written twice so each host pins a distinct file:

| Host | Manifest pin | File |
| ---- | ------------ | ---- |
| Cursor | `.cursor-plugin/plugin.json` → `"mcpServers": "./mcp.json"` | [`mcp.json`](./mcp.json) |
| Claude Code | `.claude-plugin/plugin.json` → `"mcpServers": "./.mcp.json"` | [`.mcp.json`](./.mcp.json) |

Both files are:

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

`scan.path` and `project_root` arguments are **absolute** filesystem paths.

## Install

### Cursor Marketplace (after public listing)

This plugin is **authored here**; it is not listed until Cognium Labs submits it and Cursor finishes review.

Once listed, install from **Customize** (search `cognium-dev` or Cognium SAST).

Submit / update listing: https://cursor.com/marketplace/publish

Cursor **manually reviews** public marketplace listings. The GitHub repository must stay **public**.

### Cursor team marketplace (import this repo)

On Teams / Enterprise:

1. Dashboard → **Plugins** → **Add Marketplace** → **Import from Repo**
2. Import https://github.com/cogniumhq/cognium-dev
3. Cursor reads [`.cursor-plugin/marketplace.json`](../../.cursor-plugin/marketplace.json) at the repo root and loads `plugins/cognium-dev`

Importing this repository clones the full cognium-dev monorepo (SAST engine, WASM grammars, tests). That is fine for team import. For official public marketplace review, a slim dedicated public repo may be easier for reviewers. Canonical plugin files remain in this package.

### Cursor local test (`~/.cursor/plugins/local`)

From [Cursor plugin docs](https://cursor.com/docs/plugins):

1. Copy or symlink **this plugin directory** (the folder that contains `.cursor-plugin/plugin.json`), not the monorepo root:

   ```bash
   mkdir -p ~/.cursor/plugins/local
   ln -s /path/to/cognium-dev/plugins/cognium-dev ~/.cursor/plugins/local/cognium-dev
   ```

2. Reload the window: **Developer: Reload Window**
3. Open **Customize** and confirm plugin `cognium-dev`, MCP server `cognium`, skills, rules, commands, and the SAST reviewer agent

On Teams and Enterprise, admins must allow **Allow Local Plugin Imports**. If a marketplace plugin with the same name is already installed, that install wins over the local copy.

### Claude Code

Add this GitHub repo as a marketplace, then install the plugin:

```text
/plugin marketplace add cogniumhq/cognium-dev
/plugin install cognium-dev@cognium
```

Claude Code reads [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json) (`name`: `cognium`, not an Anthropic reserved name) and the plugin at `./plugins/cognium-dev`.

Requires **Node.js ≥ 20.19.0** so `npx` can start `@cognium/mcp-server`.

Community directory (not the invite-only official catalog):

- https://platform.claude.com/plugins/submit
- https://claude.ai/admin-settings/directory/submissions/plugins/new

`claude-plugins-official` is invite-only / Anthropic-curated. Submit to the **community** directory. Official docs: https://code.claude.com/docs/en/plugins and https://code.claude.com/docs/en/plugin-marketplaces

Validate locally (Claude Code CLI):

```bash
claude plugin validate ./plugins/cognium-dev
claude plugin validate .
```

### OpenAI ChatGPT / Codex (skills only)

OpenAI does **not** accept local stdio MCP. Full tool calling needs a public HTTPS streamable-HTTP endpoint that **this repo does not provide**. Do not invent a hosted URL.

Until that endpoint exists, upload **Skills only** (`.claude-plugin/plugin.json` + `skills/*/SKILL.md`). Portal steps, listing copy (display name and short description ≤30 characters), zip command, and test prompts: [openai/README.md](./openai/README.md).

Guide: https://developers.openai.com/plugins/guides/submit-claude-plugin

## MCP tools

| Tool | Purpose |
| ---- | ------- |
| `scan` | Polyglot SAST on a file or directory |
| `explain_finding` | CWE metadata, remediation, sanitizer suggestions |
| `taint_paths` | Cross-file taint flows |
| `list_entry_points` | Attacker-reachable handlers |
| `list_reachable_sinks` | Sinks with a confirmed taint flow |
| `attack_surface_summary` | Entry points × sinks × taint paths |
| `check_sanitizer` | Whether a function is a cataloged sanitizer |
| `describe_sink` / `describe_source` | Canonical sink or source category |
| `find_similar` | Same `rule_id` / sink type elsewhere |
| `refresh` | Invalidate the analysis cache |

## Submit checklists

This PR authors the plugin. It does **not** publish listings.

### Cursor

https://cursor.com/marketplace/publish

- [x] `.cursor-plugin/plugin.json` (`cognium-dev`), pinned to `mcp.json`
- [x] Repo-root `.cursor-plugin/marketplace.json`
- [x] 1:1 logo with solid `#0B1220` plate
- [x] MIT, no secrets
- [ ] Local test (Customize)
- [ ] Submit after merge to `main`

Copy-ready Cursor form values are in the pull request description.

### Claude Code (community)

https://platform.claude.com/plugins/submit · https://claude.ai/admin-settings/directory/submissions/plugins/new

- [x] `.claude-plugin/plugin.json` (only `plugin.json` inside `.claude-plugin/`)
- [x] `.mcp.json` pinned via `"mcpServers": "./.mcp.json"`
- [x] Repo-root `.claude-plugin/marketplace.json` (`name`: `cognium`, source `./plugins/cognium-dev`)
- [ ] `claude plugin validate` on a machine with the CLI
- [ ] Community submit (not `claude-plugins-official`)

### OpenAI

https://developers.openai.com/plugins/guides/submit-claude-plugin

- [x] Skills-only archive layout (nonempty Claude `description` + `skills/*/SKILL.md`)
- [x] [openai/README.md](./openai/README.md) with portal steps and test prompts
- [ ] Skills-only zip upload (do not commit the zip)
- [ ] With MCP: **blocked** until a public HTTPS MCP exists (do not invent a URL)

## Layout

```
cognium-dev/                            # git root
├── .cursor-plugin/marketplace.json     # Cursor team marketplace
├── .claude-plugin/marketplace.json     # Claude Code marketplace (name: cognium)
└── plugins/cognium-dev/
    ├── .cursor-plugin/plugin.json      # Cursor: mcp.json, rules, logo
    ├── .claude-plugin/plugin.json      # Claude: .mcp.json (only file in this dir)
    ├── mcp.json                        # Cursor stdio MCP
    ├── .mcp.json                       # Claude stdio MCP (same command)
    ├── skills/
    ├── rules/                          # Cursor
    ├── commands/
    ├── agents/
    ├── assets/logo.svg
    ├── openai/README.md                # OpenAI skills-only submit
    └── README.md
```

## License

MIT © [Cognium Labs](https://cognium.dev)
