/**
 * LibraryProfileXssGatePass — cognium-dev #244
 *
 * Sink-side companion to `LibraryProfileSinkGatePass` (#232, canonical
 * #112, shipped 3.152.0). Where #112 drops entire `SinkType`s under
 * `library/*` (currently `log_injection`), this pass narrows the
 * `xss` `SinkType` on a per-receiver-class basis: `TaintSink`s whose
 * simple-name receiver class is in `XSS_NON_HTML_OUTPUT_CLASSES` are
 * dropped before flow generation.
 *
 * Motivation:
 *
 *   The current `xss` sink class treats any `String`-valued method
 *   receiver as a potential CWE-79 sink. Under `library/*` this
 *   over-collects by ~100x. A 10-repo Tier 2 library-profile audit
 *   (cognium-ai#189 §3, 2026-07) surfaced 507 H+C findings across
 *   hutool, xdocreport, languagetool, AndroidAsync, Sentinel,
 *   mybatis-plus, flyingsaucer, jedis — **zero** of which are actual
 *   HTML-output sinks. The 507 decompose as:
 *
 *     - 149 (29.4%) `StringBuilder.append` / `StringBuffer.append` —
 *       in-memory buffers, not HTML output.
 *     - 66  (13.0%) `PrintStream.println` on `System.out` / `System.err` —
 *       CLI stdio, not HTML output.
 *     - 43  ( 8.5%) `response.body()` on `HttpRequest` / `HttpResponse` —
 *       outbound HTTP client body READ — a taint SOURCE, not sink.
 *     - 27  ( 5.3%) `response.end()` header terminator (AndroidAsync).
 *     - 26  ( 5.1%) `HttpSession.setAttribute` — session store IO.
 *     - 33  ( 6.5%) `write` on jedis wire-protocol writers.
 *     - 91  (17.9%) other (Loggers, JSON parsers, Netflix Zuul
 *       `RequestContext`, Sentinel `Context`).
 *
 *   All eight buckets are `library/*` internal buffer / IO / logger /
 *   HTTP-client / router / JSON-parser plumbing. No web-app response
 *   writes reach `HttpServletResponse.getWriter().println(taint)` or
 *   a template renderer.
 *
 * Where #112 targets the whole vulnerability class (`log_injection`
 * is off-topic for every library), CWE-79 is legitimate for library
 * code that writes HTML (Thymeleaf, FreeMarker, Velocity, JSP
 * fragments); it is only the RECEIVER SHAPE that is off-topic.
 * Hence a class-level allowlist would over-drop and a class-level
 * denylist is the calibrated response.
 *
 * Pipeline slot: runs immediately after `LibraryProfileSinkGatePass`
 * (#112) and before `TaintPropagationPass` (so no dropped sink ever
 * reaches the flow generators). Ordering ensures both library-profile
 * gates fire under the same predicate before flow synthesis.
 *
 * Guardrails:
 *   - Pass is a no-op when `graph.ir.meta.projectProfile` is absent,
 *     `'unknown'`, or does not start with `library/`. Callers that do
 *     not opt in to profile detection get the unmodified sink list.
 *   - Only `xss`-type sinks are eligible; every other `SinkType`
 *     (`sql_injection`, `command_injection`, `path_traversal`,
 *     `deserialization`, …) is preserved unconditionally.
 *   - The class denylist is intentionally conservative: it only
 *     targets classes measured with zero HTML-output flows across the
 *     10-repo cohort. `HttpServletResponse`, `JspWriter`,
 *     `ServletOutputStream`, `PrintWriter` (in servlet context),
 *     template engines (Thymeleaf `SpringWebContext`, FreeMarker
 *     `Environment`, Velocity `VelocityContext`) are **not** on the
 *     denylist and continue to fire.
 *   - Guarded on `disabledPasses.has('library-profile-xss-gate')` at
 *     the pipeline registration site.
 *
 * Reference:
 *   - cognium-dev#244 — this ticket.
 *   - cognium-dev#232 (#112, 3.152.0) — sink-side profile gate template.
 *   - cognium-ai#189 §3 — Tier 2 library-profile CWE-79 audit.
 *   - `docs/ARCHITECTURE.md` ADR-011.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { ProjectProfile, TaintSink } from '../../types/index.js';
import type { SinkFilterResult } from './sink-filter-pass.js';

/**
 * Simple-name receiver classes for which `xss` sinks are dropped
 * under `library/*` profile. Each entry was measured with zero
 * true-positive HTML-output flows across the 10-repo Tier 2 cohort
 * (cognium-ai#189 §3, 2026-07).
 *
 * Extending this set is a deliberate, reviewable change. Adding an
 * entry risks false-negative regressions on the OWASP Benchmark
 * Java, SecuriBench Micro, and Juliet CWE-79 recall guards.
 */
const XSS_NON_HTML_OUTPUT_CLASSES: ReadonlySet<string> = new Set<string>([
  // In-memory buffers — no HTML output surface.
  'StringBuilder',
  'StringBuffer',
  'CharArrayWriter',
  'ByteArrayOutputStream',
  // CLI stdio — CLI apps, not web response bodies.
  'PrintStream',
  'System',
  // HTTP client builders — these are taint SOURCES (outbound reads),
  // not XSS sinks. `response.body()`, `.post()`, `.get()` on
  // hutool `HttpRequest` / `HttpResponse` reach us as sink
  // matches only because xss.yaml catches String-valued receivers.
  'HttpRequest',
  'HttpRequestBuilder',
  'HttpResponse',
  // Servlet non-body IO. `HttpSession.setAttribute`, `HttpSession.putValue`,
  // `HttpServletRequest.setAttribute` are session/request attribute
  // IO, not HTML output. Under `library/*` there is no JSP renderer
  // reflecting them back. `HttpServletResponse` itself is NOT on
  // this list — its writers are genuine XSS sinks.
  'HttpSession',
  'ServletRequest',
  'HttpServletRequest',
  // Wire-protocol writers (jedis internal).
  'RedisOutputStream',
  'SafeEncoder',
  'RESP2',
  'Protocol',
  // JSON parsers — these read JSON into POJOs. Source, not sink.
  'JSONUtil',
  'JSON',
  'ObjectMapper',
  'JsonReader',
  // Loggers — log injection is CWE-117 (already covered by #112);
  // these appear here because xss.yaml has a String-valued catch-all
  // that hits Logger receivers.
  'Logger',
  'LoggerFactory',
  'Log',
  'Slf4jLogger',
  // Router / interceptor context stores. Zuul `RequestContext`,
  // Sentinel `Context` are internal request-processing state, not
  // HTML output.
  'RequestContext',
  'Context',
]);

export interface LibraryProfileXssGateResult {
  /**
   * Resolved `ProjectProfile` observed on `graph.ir.meta.projectProfile`
   * at the time this pass ran. `undefined` when no profile was
   * supplied by the caller.
   */
  profile: ProjectProfile | undefined;
  /**
   * Whether the profile matched the library-shape trigger and the
   * gate was applied. `false` for every non-library shape and for
   * `'unknown'` / absent profiles.
   */
  applied: boolean;
  /**
   * Number of `xss` sinks removed from the authoritative sink list.
   * Zero when `applied === false`.
   */
  dropped: number;
  /**
   * Breakdown of drops by receiver class (simple name). Empty object
   * when `applied === false` or when no drops fired.
   */
  droppedByClass: Record<string, number>;
}

/**
 * Returns true when the resolved profile begins with `library/`
 * (i.e. any `library/production`, `library/dev`, `library/sample`,
 * `library/benchmark`, `library/test` environment binding).
 * `'unknown'` and non-library shapes return false.
 */
function isLibraryShape(profile: ProjectProfile | undefined): boolean {
  if (!profile || profile === 'unknown') return false;
  return profile.startsWith('library/');
}

export class LibraryProfileXssGatePass
  implements AnalysisPass<LibraryProfileXssGateResult>
{
  readonly name = 'library-profile-xss-gate';
  readonly category = 'security' as const;

  run(ctx: PassContext): LibraryProfileXssGateResult {
    const { graph } = ctx;
    const profile = graph.ir.meta.projectProfile;

    if (!isLibraryShape(profile)) {
      return {
        profile,
        applied: false,
        dropped: 0,
        droppedByClass: {},
      };
    }

    // Authoritative sink list mirrors the fetch pattern in
    // `LibraryProfileSinkGatePass` and `SinkSemanticsPass`: prefer
    // `SinkFilterResult.sinks` (what `analyzer.ts` assembles the
    // final `taint.sinks` from), fall back to `graph.ir.taint.sinks`
    // for stand-alone unit tests that don't run `SinkFilterPass`.
    const sinks: TaintSink[] = ctx.hasResult('sink-filter')
      ? ctx.getResult<SinkFilterResult>('sink-filter').sinks
      : graph.ir.taint.sinks;

    if (sinks.length === 0) {
      return {
        profile,
        applied: true,
        dropped: 0,
        droppedByClass: {},
      };
    }

    const droppedByClass: Record<string, number> = {};
    const kept: TaintSink[] = [];
    for (const sink of sinks) {
      if (sink.type === 'xss' && sink.class && XSS_NON_HTML_OUTPUT_CLASSES.has(sink.class)) {
        droppedByClass[sink.class] = (droppedByClass[sink.class] ?? 0) + 1;
        continue;
      }
      kept.push(sink);
    }

    const dropped = sinks.length - kept.length;

    // Mutate the array in place so downstream passes see the
    // filtered list. Preserves array identity for any consumer that
    // captured a reference before this pass ran.
    if (dropped > 0) {
      sinks.length = 0;
      sinks.push(...kept);
    }

    return {
      profile,
      applied: true,
      dropped,
      droppedByClass,
    };
  }
}
