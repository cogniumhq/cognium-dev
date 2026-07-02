/**
 * SourceSemanticsPass — cognium-dev #138
 *
 * Tags every entry in `graph.ir.taint.sources` with three optional
 * booleans (`constant`, `spi`, `demoPath`) that downstream passes use
 * to drop or downgrade false-positive taint flows:
 *
 *   Filter 1 — Constant folding
 *     `String API_KEY = "abc";` / `static final String KEY = "abc";` /
 *     `String v = SomeEnum.VALUE;` → `constant = true`.
 *     A compile-time constant string cannot carry attacker-controlled
 *     data, so it is dropped for every taint sink type. The
 *     hardcoded-credential rule continues to fire (that is precisely
 *     the point of that rule).
 *
 *   Filter 2 — SPI (Service Provider Interface)
 *     `ServiceLoader.load(Plugin.class)` /
 *     `ServiceLoader.loadInstalled(...)` / `ServiceLoader.stream(...)` /
 *     `Class.forName(name)` co-located with a
 *     `.getResources("META-INF/services/…")` lookup within ±30 lines
 *     of the same method → `spi = true`. SPI-loaded values are
 *     provider-controlled configuration, not attacker input.
 *
 *   Filter 3 — Demo path
 *     Path components matching `demo`, `example(s)`, `samples`,
 *     `integration-tests`, or `integration_tests` (case-insensitive)
 *     → `demoPath = true` on every source in the file. This tag is
 *     never used to drop flows — `scan-secrets-pass` consumes it to
 *     downgrade hardcoded-credential findings on demo paths from
 *     `high` → `info` and `warning/error` → `note`.
 *
 * This pass is a pure source-tagger: it never emits SAST findings and
 * never removes sources from `graph.ir.taint.sources`. All
 * consumption is downstream (findings.ts, taint-propagation-pass,
 * scan-secrets-pass).
 *
 * Consumption policy is documented on the `TaintSource` type
 * (`src/types/index.ts`) and in `findings.ts:sourceSemanticsAllowed`.
 *
 * Pipeline slot: runs after `LanguageSourcesPass` (so the full source
 * list is available) and before `TaintPropagationPass` (so the tags
 * are visible to flow generation).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TaintSource } from '../../types/index.js';

/**
 * Path-component regex used by both this pass (source tagging) and
 * `scan-secrets-pass` (severity downgrade). Matches when any path
 * segment equals one of the demo/example/samples/integration-tests
 * tokens, case-insensitive. A bare filename like `DemoParser.java`
 * does NOT match (no leading or trailing path separator).
 */
export const DEMO_PATH_RE =
  /(?:^|\/)(?:demo|example|examples|samples|integration-tests|integration_tests)(?:\/|$)/i;

// ---------------------------------------------------------------------------
// Filter 1 — Constant
// ---------------------------------------------------------------------------

// `[final ] TYPE ident = "string literal";` — canonical simple form.
// Allows generics / arrays in the type position (`List<String>`, `String[]`).
const CONST_STRING_ASSIGN_RE =
  /^\s*(?:final\s+|static\s+final\s+)?[A-Za-z_][\w.<>\[\]]*\s+[A-Za-z_]\w*\s*=\s*"[^"]*"\s*;?\s*$/;

// `[public|private|protected ] static final TYPE ident = <literal-or-simple-expr>`
// The RHS check gates on either a string literal, a numeric/boolean literal,
// or a bare identifier reference (constant reference chain). We intentionally
// accept the presence of `static final` as a strong signal — Java's language
// rules already ensure the value is compile-time constant or effectively so.
const STATIC_FINAL_RE =
  /^\s*(?:public\s+|private\s+|protected\s+)?static\s+final\s+/;

// `ident = SomeEnum.VALUE;` — enum constant reference. Requires an
// UPPER_CASE constant identifier after the dot to avoid matching
// regular field access like `user.name`. The type identifier (LHS of
// the dot) is allowed to be either PascalCase (`SomeEnum`) or
// SCREAMING_SNAKE (`SOME_ENUM`) — both are common in Java / Kotlin
// enum types.
const ENUM_CONST_REF_RE = /=\s*[A-Z][A-Za-z0-9_]*\.[A-Z][A-Z0-9_]*\s*;?\s*$/;

function isConstantSource(code: string | undefined): boolean {
  if (!code) return false;
  if (CONST_STRING_ASSIGN_RE.test(code)) return true;
  if (STATIC_FINAL_RE.test(code)) {
    // For static final, require the RHS to look like a literal or a
    // simple constant reference (no method calls / no `new`).
    const rhs = code.split('=').slice(1).join('=').trim();
    if (rhs.length === 0) return false;
    if (/^"[^"]*"\s*;?\s*$/.test(rhs)) return true; // string literal
    if (/^-?\d+(?:\.\d+)?[fFdDlL]?\s*;?\s*$/.test(rhs)) return true; // numeric
    if (/^(?:true|false)\s*;?\s*$/.test(rhs)) return true; // boolean
    if (/^[A-Za-z_][\w.]*\s*;?\s*$/.test(rhs)) return true; // ident ref
    return false;
  }
  if (ENUM_CONST_REF_RE.test(code)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Filter 2 — SPI
// ---------------------------------------------------------------------------

const SERVICE_LOADER_RE =
  /\bServiceLoader\.(?:load|loadInstalled|stream)\s*\(/;

const CLASS_FOR_NAME_RE = /\bClass\.forName\s*\(/;

const META_INF_SERVICES_RE = /getResources?\s*\(\s*"META-INF\/services\//;

/**
 * SPI window size (lines). Matches the ±30-line window that
 * `sink-filter-pass.ts` Stage 9f uses for the same co-location check.
 */
const SPI_WINDOW = 30;

function isSpiSource(source: TaintSource, lines: string[]): boolean {
  const code = source.code;
  if (!code) return false;
  if (SERVICE_LOADER_RE.test(code)) return true;
  if (CLASS_FOR_NAME_RE.test(code)) {
    // Check for META-INF/services lookup within ±SPI_WINDOW lines of
    // the source line. `source.line` is 1-indexed.
    const start = Math.max(0, source.line - 1 - SPI_WINDOW);
    const end = Math.min(lines.length, source.line - 1 + SPI_WINDOW + 1);
    for (let i = start; i < end; i++) {
      if (META_INF_SERVICES_RE.test(lines[i]!)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Filter 3 — DemoPath
// ---------------------------------------------------------------------------

function isDemoPathFile(file: string | undefined): boolean {
  if (!file) return false;
  return DEMO_PATH_RE.test(file);
}

// ---------------------------------------------------------------------------
// Pass
// ---------------------------------------------------------------------------

export interface SourceSemanticsResult {
  /** Number of sources tagged with `constant = true`. */
  constantCount: number;
  /** Number of sources tagged with `spi = true`. */
  spiCount: number;
  /** Number of sources tagged with `demoPath = true`. */
  demoPathCount: number;
}

export class SourceSemanticsPass
  implements AnalysisPass<SourceSemanticsResult>
{
  readonly name = 'source-semantics';
  readonly category = 'security' as const;

  run(ctx: PassContext): SourceSemanticsResult {
    const { graph, code } = ctx;
    const sources = graph.ir.taint.sources;
    if (sources.length === 0) {
      return { constantCount: 0, spiCount: 0, demoPathCount: 0 };
    }

    const file = graph.ir.meta.file;
    const demoPath = isDemoPathFile(file);
    const lines = code.split('\n');

    let constantCount = 0;
    let spiCount = 0;
    let demoPathCount = 0;

    for (const source of sources) {
      if (isConstantSource(source.code)) {
        source.constant = true;
        constantCount++;
      }
      if (isSpiSource(source, lines)) {
        source.spi = true;
        spiCount++;
      }
      if (demoPath) {
        source.demoPath = true;
        demoPathCount++;
      }
    }

    return { constantCount, spiCount, demoPathCount };
  }
}
