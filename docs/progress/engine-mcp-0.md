# engine-mcp — Phase 0 (intake)

**INTERNAL.** Only **Cognium** is external.

**Date:** 2026-10-01 · **Track:** `engine-mcp` (`techspec/briefs/2026-10-01-engine-one-server.md`) · **Phase:** 0, intake · **Gate:** none (the phase is a fact check) · **Result:** facts confirmed, four snapshot numbers restamped, seven things found in code that the map did not have.

## What was built

Nothing shipped — Phase 0 is intake. Two worktrees off `origin/main`, both on `track/engine-mcp/1`:

| Worktree | Repo | Base |
|---|---|---|
| `~/work/cogniumhq/cognium-dev-engine-mcp` | `cogniumhq/cognium-dev` | `origin/main` **b2ce517** |
| `~/work/cogniumhq/cognium-ai-engine-mcp` | `cogniumhq/cognium-ai` | `origin/main` **ff0d2d46** |

## The brief's facts — confirmed

Read from the manifests and sources in those two worktrees, not from npm:

- **No library depends on a server.** `circle-ir` depends on `web-tree-sitter` and `yaml`; `circle-ir-ai` on `circle-ir`, `@ax-llm/ax`, `@mastra/core`, `@aws-sdk/client-s3`, `@cognium/project-profile-detect`, `minimatch`, `p-queue`. Neither CLI depends on a server either.
- **`circle-pack` is the only code consumer of a server** — `circle-pack/src/api/routes/mcp.ts`. Every other hit for a server package name is a changelog, a README, a `.specifica` file or a plugin manifest that spawns it through `npx`.
- **The tool names do not overlap.** 11 in `@cognium/mcp-server` (`scan`, `explain_finding`, `taint_paths`, `list_entry_points`, `check_sanitizer`, `describe_sink`, `describe_source`, `attack_surface_summary`, `list_reachable_sinks`, `find_similar`, `refresh`) and 10 in `@cognium-ai/mcp-server`, matching `spec.md` §2 exactly.
- **The seam is shallow.** Both servers already register through the same SDK call, `server.registerTool(name, config, handler)`, so wrapping the 10 ai tools as a `ToolModule` is mechanical. `circle-ir-ai` has no `./mcp` export yet (exports `.`, `./specifica/*`, `./components`).

## The brief's snapshot numbers — four had moved

| | Brief / `spec.md` §1.2 said | Code says (10-01) |
|---|---|---|
| `@cognium/mcp-server` | 0.1.18 | **0.1.21** |
| cognium-ai fleet on `main` | 4.16.5 | **4.16.4**, pinning `circle-ir` **4.9.27** |
| the pin drift | dev 4.9.29 vs ai 4.9.28 | dev 4.9.29 vs ai **4.9.27**; the pushed but unmerged `chore/circle-ir-4.9.28` (head **7a5e7acc**) already carries the whole ai fleet at **4.16.5 on 4.9.29** — uniform with cognium-dev, so the branch name is a misnomer |
| ai CLI commands | 20 | **19** |

`circle-ir` and the `cognium-dev` CLI are 4.9.29 as stated.

## The blockers, measured

- **zod 3 → 4 is small, not a blocker.** All 10 ai tools import `z`. Across them: 16 `.optional().default()` chains, one `.passthrough()` (→ `z.looseObject`), and one `z.record` that is already in v4's two-argument form. No `z.nativeEnum`, no `errorMap`, no `invalid_type_error`/`required_error`, no `preprocess`/`transform`/`effect`. The port is a day's careful work, not a redesign.
- **SDK is not uniform.** `@cognium/mcp-server` is on `^1.30.1` (with zod `^4.6.5`); `@cognium-ai/mcp-server` and `circle-pack` are on `^1.29.0`; `@cogniumhq/conformance` pins `1.29.0` exactly in dev dependencies. #18's pin check has to cover the SDK, not only `circle-ir`.
- **The pin drift does not trip the refusal.** The refusal is specified at *minor* granularity (`spec.md` §1.2 pin rule). 4.9.29 against 4.9.27 is one minor, so the load-time refusal would pass it and the pin-uniformity CI gate is what catches it. The refusal test needs a synthetic cross-minor fixture. See the open questions.

## Found in code, not in the map

1. **`@cognium/mcp-server` is not importable as a library.** Its `exports["."]` resolves to `dist/index.js`, which is the stdio bin and calls `main()` at import, so importing the package starts a server on the host's stdin/stdout. #15a must split a library entry from the bin before anything can pass `{ modules }` — and before `circle-pack` can swap onto it. `@cognium-ai/mcp-server` already has the shape to copy: `export { buildServer }` plus an `isMain` guard that resolves `process.argv[1]` through `realpathSync` (the npm bin-symlink trap, documented in its own comment).
2. **There is no "startup" to compute enablement at, under `circle-pack`.** `/api/mcp` runs the SDK's stateless mode — a fresh `McpServer` and transport per request. Enablement has to be memoized per process, reused by every request-scoped server, and the state-1 notice printed once per process.
3. **The shared `ProjectCache` has nowhere to land in the ai module.** `design.md` §1 says a module reads IR from the server's cache instead of parsing again, but the `circle-ir-ai` ops the module would wrap take a repo path and do their own file detection — `generateBom(repoPath, opts)`, with `GenerateBomOptions` exposing only `dependencies` and `skipFiles`. Either the ops gain an optional analysis argument or the module shares the handle without reuse.
4. **Server identity is hardcoded, and divergent.** `buildServer` in cognium-dev announces `cognium-mcp-server` / `0.1.0`; the ai server announces `cognium-mcp` / `0.4.0`. Both are stale against their packages (0.1.21, 4.16.4). The `initialize` result carries these, so the one-answer gate cannot pass until they come from one place.
5. **`/api/mcp` is closed by default.** It is gated on `Authorization: Bearer $MCP_AUTH_TOKEN` and returns 503 when `MCP_AUTH_TOKEN` is unset, while REST on the same host is open and unauthenticated. The one-answer harness must set it; the asymmetry is #12's to resolve.
6. **The two CLIs are not subset and superset.** `cognium-dev` has 6 commands (`version`, `init`, `list-passes`, `metrics`, `sbom`, `scan`); `cognium-ai` has 19. `sbom` (CycloneDX/SPDX output) and `list-passes` exist **only** in `cognium-dev` — `cognium-ai`'s `bom` is the 9-layer Layer-BOM, a different surface, and its `sbom-generation` is a pass inside `trust` that emits an informational finding, not an SBOM file. `cognium-ai` already ships `doctor`, `init` and `version`, so #17 extends `doctor` rather than adding it. The dev CLI also hand-rolls its argument parsing while `cognium-ai` uses commander, so porting those two commands is a rewrite, not a move.
7. **#15b has less to move than written, and more.** `bench/` is not in git — four files (`h2h.mjs`, `honest.mjs`, `probe.mjs`, `README.md`) sit untracked in Eyal's main checkout, so `git subtree split` would carry nothing. Conversely the plugin's marketplace manifests live at the repo root (`.claude-plugin/marketplace.json`, `.cursor-plugin/marketplace.json`) as well as under `plugins/cognium-dev/`, and `release.sh` names `packages/mcp-server` at lines 95–101.

Also noted, as doc debt inside code rather than a finding: `circle-pack/src/api/routes/mcp.ts`'s docstring says "the 9 MCP tools" and lists 9, omitting `layer_bom`; the server registers 10.

## What cognium-dev CI already carries into `cognium-mcp`

`design.md` §7 lists eight jobs for the new repo. `ci.yml` on b2ce517 already has six of the building blocks: lint, build + typecheck, a per-package vitest matrix with coverage thresholds, self-scan (SAST, gated on high/critical, full report advisory), a production dependency audit, and a pack dry-run that verifies entrypoints. New in #15b: one-answer, three-state, module refusal, MCP conformance (non-gating), and a manifest diff that asserts no PolyForm file. The `@cognium/mcp-server` suite is six vitest files (`cache`, `catalogs`, `server`, `tools`, `tools-analysis`, `tools-filters-cache`).

## Tests run

None. Phase 0 read code and manifests; no install, no build, no suite. The Phase 1 gate ("mcp-server suite green") is the first measurement, and the suites were left untouched so that baseline is taken against an unmodified tree.

## Deviations from the techspec

None in substance. The four restamped numbers and the seven findings above are recorded in the files this track owns:

- `spec.md` §1.2 — rewritten with the measured table, SHAs and dependency facts; §7's one-answer bullet now names the two harness preconditions (finding 4 and 5); status line restamped.
- `design.md` §1 — the two gaps between the picture and the code (findings 1 and 3); §6 — where "once at startup" actually lands (finding 2); §7 — what cognium-dev CI already has, and the SDK pin spread.
- `tasks.md` — rows #15a, #15b, #17, #18 carry their Phase 0 notes, and a "Status on 10-01 — engine-mcp track, Phase 0" block sits above the owner's block rather than editing it.
- `services/cognium-engine/README.md` — the four doc-debt items this track owns are restamped: prod/#11, the two-doors item (#9 decided, #15 split), goal 2's `#9 deferred`, and `bench/`.

One doc-debt line was left alone on purpose: "`cognium-dev` is defined three ways", which turns on `reference/cognium-ai.md` §3.5 and an `archive/` citation. The live text already says principles §4 wins; correcting the reference page is not on this track's path and would be a guess at what §3.5 should say instead.

No rule in the specification was changed. Where code and the specification disagree, it is an open question below.

## Eyal-only actions

Batched, none blocking Phase 1:

1. **Merge or close `chore/circle-ir-4.9.28`** (pushed, head 7a5e7acc). It carries the ai fleet at 4.16.5 on `circle-ir` 4.9.29 and would make the fleet pin uniform with cognium-dev. Phase 2 swaps `circle-pack`'s dependency and will rebase onto whatever `main` holds — one unmerged release branch is one more rebase. The branch name no longer matches its contents.
2. **Commit `cognium-dev/bench/`** (four untracked files in the main checkout) if those scripts are to travel into `cognium-mcp` with history under #15b. Otherwise say so and they are authored fresh there.
3. **Close `chore/release-4.16.4-redos`**, which `tasks.md` #11 records as behind `main`.
4. **The #11 prod roll** stays yours (`/health` by digest); the brief's default is one roll, to 4.16.5.

Nothing in Phase 0 published, deployed, created a repo or hostname, or touched prod.

## Open questions

1. **Does the load-time refusal stay at minor granularity?** `spec.md` §1.2 says the server refuses an ai module built against a different `circle-ir` **minor**, and calls today's drift "the drift the one-server design must refuse at load". Those two statements disagree: the real drift is 4.9.29 against 4.9.27, one minor, which a minor-granularity check accepts. Either the rule tightens to the exact pin the fleet already enforces in CI, or §1.2's sentence about this drift goes. Default taken for now: the rule as written stands, the refusal test uses a synthetic cross-minor fixture, and §1.2's claim about *this* drift is corrected to name the pin-uniformity gate instead. Rules are not changed by this track.
2. **`sbom` and `list-passes` — ported or dropped?** Retiring the `cognium-dev` CLI to a shim (#17) removes two working commands that `cognium` does not have. Default taken if there is no answer by Phase 4: port both, since the brief's done-criterion is one CLI and a shim that silently loses commands is a regression a user meets, not a rename.
3. **Do the `circle-ir-ai` ops gain an injected analysis, so the shared cache is real?** It decides whether Phase 2 touches `circle-ir-ai` internals or only wraps them. Default if unanswered: wrap only, declare in the Phase 2 report that the cache is shared in handle but not in effect, and leave the injection as an engine-owner row — the one-answer and three-state gates do not depend on it.

## Next step, exactly

Phase 1, #15a loader, in `cognium-dev-engine-mcp` on a branch stacked on this one:

1. Split `packages/mcp-server`'s library entry from its bin, export `buildServer`, `ToolModule`, `ToolContext` and `ProjectCache` from the package root, and keep the stdio bootstrap behind an `isMain` guard — finding 1, and the prerequisite for everything else in #15a.
2. Take server name and version from `package.json` in one place — finding 4.
3. Add `ToolModule` `{ id, version, licence, circleIrRange, register(server, ctx) }`, `buildServer({ modules })`, and `ctx = { cache, enablement }` with enablement memoized per process — findings 2 and 3.
4. Guarded `import('circle-ir-ai/mcp')`; refusal on a `circle-ir` minor mismatch with one line, server stays up floor-only.
5. Tests: three-state matrix (floor · extended-no-endpoint · extended-with-endpoint · commercial with a test key), the refusal with a synthetic cross-minor fixture, and `npm pack` manifest diff.
6. Gate: the mcp-server suite green and 0.2.0 ready, not published.
