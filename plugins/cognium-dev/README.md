# Cognium SAST (Cursor plugin)

Cursor plugin for **cognium-dev**, the MIT-licensed OSS SAST scanner from [Cognium Labs](https://cognium.dev). After install, a Cursor agent can run deterministic taint analysis on the workspace through [`@cognium/mcp-server`](https://www.npmjs.com/package/@cognium/mcp-server), explain findings, and propose sanitizer-backed **defensive** fixes.

This plugin is **not** listed on the public Cursor Marketplace until someone submits it. Authoring lives in this monorepo.

- Homepage: https://cognium.dev
- Repository: https://github.com/cogniumhq/cognium-dev
- License: **MIT** (free, public-repo-friendly; not GPL)
- Identifier: `cognium-dev` (v0.1.0)
- Logotype (1:1 SVG, solid `#0B1220` plate): [`assets/logo.svg`](./assets/logo.svg)

After this lands on `main`, the raw GitHub URL for the marketplace publish form is:

```
https://raw.githubusercontent.com/cogniumhq/cognium-dev/main/plugins/cognium-dev/assets/logo.svg
```

That URL 404s until the plugin is merged to `main`.

## What you get

| Component | Name | Role |
| --------- | ---- | ---- |
| MCP | `cognium` | Stdio server: `npx -y @cognium/mcp-server` (no API keys) |
| Skills | `cognium-workspace-scan`, `cognium-taint-triage` | Scan + report; triage taint paths and propose a sanitizer-backed fix |
| Rules | `prefer-cognium-sast`, `defensive-remediation` | Prefer engine tools over guessed vulns; verify sanitizers before patching |
| Commands | `/cognium-scan`, `/cognium-attack-surface` | Scan the workspace; summarize entry points, reachable sinks, and taint paths |
| Agent | `cognium-sast-reviewer` | Security review that calls MCP tools instead of free-styling advice |

Suggested tool-call flow (same as the MCP README):

1. `scan` the project root (absolute path)
2. `attack_surface_summary`
3. `explain_finding` on the highest-severity findings
4. `find_similar`
5. `check_sanitizer` before proposing a fix

Languages: Java, JavaScript, TypeScript, Python, Go, Rust, Bash, HTML.

This is a **defensive** SAST plugin. Skills, rules, agents, and commands help you scan, explain, triage, and remediate. They do not include exploit steps, payloads, or attack procedures.

## Requirements

- **Node.js ≥ 20.19.0** on the PATH (the MCP server is started with `npx`)
- Network access to npm the first time `npx` fetches `@cognium/mcp-server`
- No secrets, tokens, or plugin variables

## Install

### Cursor Marketplace (after public listing)

This plugin is **authored here**; it is not listed on the marketplace until Cognium Labs submits it and Cursor finishes review.

Once listed, install from **Customize** (search `cognium-dev` or Cognium SAST) or from the marketplace page.

Submit / update listing: https://cursor.com/marketplace/publish

Cursor **manually reviews** public marketplace listings. The GitHub repository must stay **public**.

### Team marketplace (import this repo)

On Teams / Enterprise:

1. Dashboard → **Plugins** → **Add Marketplace** → **Import from Repo**
2. Import https://github.com/cogniumhq/cognium-dev
3. Cursor reads [`.cursor-plugin/marketplace.json`](../../.cursor-plugin/marketplace.json) at the repo root and loads `plugins/cognium-dev`

**Note:** importing this repository clones the full cognium-dev monorepo (SAST engine, WASM grammars, tests). That is fine for team import. For official public marketplace review, a slim dedicated public repo that contains only the plugin (plus this marketplace manifest) may be easier for reviewers. Canonical plugin files remain in this package; do not fork a second copy unless you are preparing that slim submit repo.

### Local test (`~/.cursor/plugins/local`)

From [Cursor plugin docs](https://cursor.com/docs/plugins):

1. Copy or symlink **this plugin directory** (the folder that contains `.cursor-plugin/plugin.json`), not the monorepo root:

   ```bash
   mkdir -p ~/.cursor/plugins/local
   ln -s /path/to/cognium-dev/plugins/cognium-dev ~/.cursor/plugins/local/cognium-dev
   ```

2. Reload the window: **Developer: Reload Window**
3. Open **Customize** and confirm:
   - Plugin `cognium-dev` / Cognium SAST
   - MCP server `cognium`
   - Skills, rules, commands, and the SAST reviewer agent

On Teams and Enterprise, admins must allow **Allow Local Plugin Imports** (Dashboard → Settings → Security & Identity → Marketplace and Plugins). If a marketplace plugin with the same name is already installed, that install wins over the local copy.

## MCP tools

The bundled `mcp.json` matches the Cursor config in [`packages/mcp-server/README.md`](../../packages/mcp-server/README.md):

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

`scan.path` and `project_root` arguments are **absolute** filesystem paths.

## Submit to the public marketplace

This PR only authors the plugin. It does **not** publish it.

1. Keep the repository public
2. Confirm local test (Customize shows MCP + components)
3. Open https://cursor.com/marketplace/publish and submit the GitHub URL
4. Wait for Cursor’s manual review (and review of later updates)

Checklist from the [plugins reference](https://cursor.com/docs/reference/plugins):

- [x] `.cursor-plugin/plugin.json` with kebab-case `name` (`cognium-dev`)
- [x] Repo-root `.cursor-plugin/marketplace.json` for team / multi-plugin import
- [x] Relative `logo` (`assets/logo.svg`) — 1:1 SVG with a solid `#0B1220` background plate (no transparent corners)
- [x] Component frontmatter (`name` / `description` as required)
- [x] `mcp.json` with no secrets and no `${VAR}` placeholders
- [x] README with install, usage, and Node requirement
- [x] MIT license (plugin stays free)
- [ ] Local test on a developer machine (symlink + Reload Window + Customize)
- [ ] Public submit at https://cursor.com/marketplace/publish (do not claim the plugin is listed until Cursor reviews it)

### Marketplace publish form (copy-ready)

Fill https://cursor.com/marketplace/publish after merge to `main`. This package does **not** submit the form.

| Field | Value |
| ----- | ----- |
| Organization name | Cognium Labs |
| Organization handle | `cognium` (no public listing at `cursor.com/marketplace/cognium`; handle uniqueness is not fully visible from public pages — if the form rejects it, try `cognium-labs`) |
| Contact email | hello@cognium.net |
| Website | https://cognium.dev |
| GitHub repository | https://github.com/cogniumhq/cognium-dev |
| Short description | Deterministic SAST for Cursor. Scan the workspace with Cognium taint analysis via MCP, explain findings, and propose sanitizer-backed defensive fixes — no API keys. |
| Logotype URL | `https://raw.githubusercontent.com/cogniumhq/cognium-dev/main/plugins/cognium-dev/assets/logo.svg` (after merge to `main`) |
| License | MIT (free) |

Cursor **manually reviews** public marketplace listings. Keep this repository **public**.

## Layout

```
cognium-dev/                          # git root
├── .cursor-plugin/marketplace.json   # team marketplace + public submit
└── plugins/cognium-dev/              # this plugin (symlink this folder locally)
    ├── .cursor-plugin/plugin.json
    ├── mcp.json
    ├── skills/
    ├── rules/
    ├── commands/
    ├── agents/
    ├── assets/logo.svg
    └── README.md
```

## License

MIT © [Cognium Labs](https://cognium.dev)
