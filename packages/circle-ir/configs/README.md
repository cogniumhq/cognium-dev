# `configs/` — documentation and export surface (not runtime)

**Nothing in `src/` reads these files.** circle-ir must run in the browser and
in Cloudflare Workers, so the library cannot touch the filesystem at all. The
taint patterns that actually drive analysis live in TypeScript:

| Surface | Location | Role |
|---|---|---|
| `DEFAULT_SOURCES` / `DEFAULT_SINKS` / `DEFAULT_SANITIZERS` / `DEFAULT_SINK_SEMANTICS` | `src/analysis/config-loader.ts` | **Canonical.** Language-agnostic by default; scope a pattern with `languages: ['python']` when its method name collides across ecosystems. |
| `LanguagePlugin.getBuiltinSources()` / `getBuiltinSinks()` | `src/languages/plugins/<lang>.ts` | Supplement for language-specific patterns that have **no** `DEFAULT_*` counterpart. `TaintMatcherPass` merges them after the canonical registry. |
| `configs/**` (this directory) | — | Documentation, and an export for downstream tools that want a machine-readable view of the ruleset. Editing a file here changes nothing about how code is analysed. |

See ADR-004 in `.specifica/mvp/design.md` for the rationale.

## Adding or fixing a pattern

Add it to `DEFAULT_SINKS` / `DEFAULT_SOURCES` in `src/analysis/config-loader.ts`
(scoped with `languages` if it is language-specific). Only reach for a plugin
builtin when the pattern genuinely has no place in the canonical registry.

Never register the same `(class, method, cwe)` in both surfaces:
`findSinks` dedupes by `location:line:cwe` and keeps the higher-confidence
match, so the duplicate is invisible — you can "fix" the copy that loses and
see no change in behaviour. That failure mode cost an extra investigation round
on Issue #4 (`yaml.safe_load`). It is now locked by
`tests/languages/sink-registry-contract.test.ts`.

## Drift

Because these files are not executable, they lag the runtime registries. To see
by how much:

```bash
npm run config:drift
```

The report lists documented sinks that no longer exist at runtime, and entries
whose vulnerability type disagrees with the code. It is informational and never
fails the build — treat a large delta as a documentation debt signal, not a bug.
