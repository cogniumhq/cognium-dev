/**
 * cognium-dev 3.164.0 — Rust derived-var sanitizer coverage.
 *
 * Prior to 3.164.0 the Rust branch of the derived-var expansion in
 * `taint-propagation-pass.ts` (mirror of Python's `buildPythonTaintedVars`
 * post-processing at lines 1043-1130) recorded the derived vars but did
 * NOT record per-alias sanitizer coverage. The `xss_safe_escaped` shape
 * from cognium-dev#249 rust-synthetic benchmark:
 *
 *   let name = req.query_string();          // http_param source
 *   let escaped = encode_text(name);        // xss sanitizer wrap
 *   let html = format!("<h1>{}</h1>", escaped);
 *   HttpResponse::Ok().body(html);          // xss sink
 *
 * was reported as an unsanitized xss flow because `aliasSanitizedFor`
 * was empty for `escaped` (and transitively `html`), so the
 * variable-scan flow emitter at ~1422 saw `html` in the sink and did
 * not short-circuit.
 *
 * These pinning tests freeze:
 *   - Positive suppression (encode_text sanitizer → no xss flow)
 *   - Negative retention (unsanitized derived flow still emits)
 *   - Mixed-operand safety (covered + raw operand → no credit)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countXss = (r: any) =>
  (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'xss').length;

describe('cognium-dev 3.164.0 — Rust derived-var sanitizer coverage', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('suppresses xss flow when derived var wraps source in encode_text() sanitizer', async () => {
    const code = `
use actix_web::{web, HttpRequest, HttpResponse};
use html_escape::encode_text;

async fn greet_safe(req: HttpRequest) -> HttpResponse {
    let name = req.query_string();
    let escaped = encode_text(name);
    let html = format!("<h1>Hello, {}!</h1>", escaped);
    HttpResponse::Ok()
        .content_type("text/html")
        .body(html)
}
`;
    const r = await analyze(code, 'xss_safe_escaped.rs', 'rust');
    expect(countXss(r)).toBe(0);
    // Sanity: the source, sink, and sanitizer are all detected.
    expect(r.taint?.sources?.length).toBeGreaterThan(0);
    expect(r.taint?.sinks?.some((s: any) => s.type === 'xss')).toBe(true);
    expect(
      r.taint?.sanitizers?.some(
        (s: any) => s.method === 'encode_text()' && s.sanitizes.includes('xss'),
      ),
    ).toBe(true);
  });

  it('still emits xss flow when derivation goes through NO sanitizer (regression guard)', async () => {
    const code = `
use actix_web::{web, HttpRequest, HttpResponse};

async fn greet_unsafe(req: HttpRequest) -> HttpResponse {
    let name = req.query_string();
    let greeting = name.to_string();
    let html = format!("<h1>Hello, {}!</h1>", greeting);
    HttpResponse::Ok()
        .content_type("text/html")
        .body(html)
}
`;
    const r = await analyze(code, 'xss_unsafe.rs', 'rust');
    expect(countXss(r)).toBeGreaterThan(0);
  });

  it('does NOT credit when compound RHS mixes a covered alias with a raw tainted operand', async () => {
    // Soundness gate: `raw` is tainted-but-uncovered and appears alongside
    // the covered `escaped` inside the format!, so `html` MUST NOT inherit
    // xss coverage — the `raw` operand is still a live flow.
    const code = `
use actix_web::{web, HttpRequest, HttpResponse};
use html_escape::encode_text;

async fn greet_mixed(req: HttpRequest) -> HttpResponse {
    let raw = req.query_string();
    let escaped = encode_text(raw);
    let html = format!("<h1>{} — {}</h1>", raw, escaped);
    HttpResponse::Ok()
        .content_type("text/html")
        .body(html)
}
`;
    const r = await analyze(code, 'xss_mixed.rs', 'rust');
    expect(countXss(r)).toBeGreaterThan(0);
  });
});
