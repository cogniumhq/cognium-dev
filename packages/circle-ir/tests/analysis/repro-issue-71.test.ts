/**
 * Regression tests for cognium-dev #71 — Rust actix-web extractor sources.
 *
 * The first three issues at parse time:
 *   1. Typed extractor regex required a bare `Path<…>` / `Query<…>` etc., but
 *      Rust actix params surface as `web::Path<String>` (and axum as
 *      `axum::extract::Path<String>`). Sources were never emitted.
 *   2. Source `type` was always `http_body`, which `canSourceReachSink` does
 *      NOT map to `path_traversal` or `ssrf` — even the Json/Body case was
 *      missing flows to those sink kinds.
 *   3. Sources lacked `variable` (the parameter / let-binding LHS), so the
 *      expression-scan flow detector skipped them entirely.
 *
 * Plus a multi-level alias hop that the Python branch had but Rust did not:
 *   let form = f.into_inner();
 *   let path = form.path;
 *   fs::write(path, …);
 * `buildRustTaintedVars` now does a fixpoint over let-bindings/assignments
 * mirroring `buildPythonTaintedVars`, so the alias chain is followed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('repro #71: Rust actix-web extractor sources', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('detects match_info().get(..) → Command::output command_injection flow', async () => {
    const code = `
use actix_web::{web, HttpRequest, HttpResponse};
use std::process::Command;

async fn handler(req: HttpRequest) -> HttpResponse {
    let id = req.match_info().get("id").unwrap_or("");
    let _ = Command::new("sh").arg("-c").arg(format!("echo {}", id)).output();
    HttpResponse::Ok().finish()
}
`;
    const r = await analyze(code, 'a.rs', 'rust');
    const flows = r.taint?.flows ?? [];
    expect(flows.some(f => f.sink_type === 'command_injection')).toBe(true);
  });

  it('detects req.uri().query() → fs::read_to_string path_traversal flow', async () => {
    const code = `
use actix_web::{web, HttpRequest, HttpResponse};
use std::fs;

async fn handler(req: HttpRequest) -> HttpResponse {
    let q = req.uri().query().unwrap_or("");
    let _ = fs::read_to_string(q);
    HttpResponse::Ok().finish()
}
`;
    const r = await analyze(code, 'b.rs', 'rust');
    const flows = r.taint?.flows ?? [];
    expect(flows.some(f => f.sink_type === 'path_traversal')).toBe(true);
  });

  it('detects web::Path<String> typed extractor → Command via alias hop', async () => {
    const code = `
use actix_web::{web, HttpResponse};
use std::process::Command;

async fn handler(name: web::Path<String>) -> HttpResponse {
    let n = name.into_inner();
    let _ = Command::new("sh").arg("-c").arg(format!("echo {}", n)).output();
    HttpResponse::Ok().finish()
}
`;
    const r = await analyze(code, 'c.rs', 'rust');
    const sources = r.taint?.sources ?? [];
    const flows = r.taint?.flows ?? [];
    // Typed extractor must surface as a source with variable=param.name.
    expect(sources.some(s => s.variable === 'name' && s.type === 'http_param')).toBe(true);
    // And the alias `n` must reach the command_injection sink.
    expect(flows.some(f => f.sink_type === 'command_injection')).toBe(true);
  });

  it('detects web::Query<T> typed extractor → reqwest::get ssrf flow', async () => {
    const code = `
use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
struct Q { url: String }

async fn handler(q: web::Query<Q>) -> HttpResponse {
    let u = q.into_inner().url;
    let _ = reqwest::get(&u).await;
    HttpResponse::Ok().finish()
}
`;
    const r = await analyze(code, 'd.rs', 'rust');
    const sources = r.taint?.sources ?? [];
    const flows = r.taint?.flows ?? [];
    expect(sources.some(s => s.variable === 'q' && s.type === 'http_param')).toBe(true);
    expect(flows.some(f => f.sink_type === 'ssrf')).toBe(true);
  });

  it('detects web::Form<T> typed extractor → fs::write path_traversal flow', async () => {
    const code = `
use actix_web::{web, HttpResponse};
use std::fs;

#[derive(serde::Deserialize)]
struct F { path: String, body: String }

async fn handler(f: web::Form<F>) -> HttpResponse {
    let form = f.into_inner();
    let _ = fs::write(&form.path, form.body.as_bytes());
    HttpResponse::Ok().finish()
}
`;
    const r = await analyze(code, 'e.rs', 'rust');
    const sources = r.taint?.sources ?? [];
    const flows = r.taint?.flows ?? [];
    expect(sources.some(s => s.variable === 'f' && s.type === 'http_param')).toBe(true);
    expect(flows.some(f => f.sink_type === 'path_traversal')).toBe(true);
  });

  it('typed-extractor source type uses http_param for Form/Query/Path (covers path_traversal/ssrf)', async () => {
    // Without the http_param mapping, the next-pass `canSourceReachSink`
    // matrix drops these flows entirely.
    const code = `
use actix_web::{web, HttpResponse};
use std::fs;

async fn h(p: web::Path<String>) -> HttpResponse {
    let s = p.into_inner();
    let _ = fs::read_to_string(&s);
    HttpResponse::Ok().finish()
}
`;
    const r = await analyze(code, 'f.rs', 'rust');
    const sources = r.taint?.sources ?? [];
    const typedSrc = sources.find(s => s.variable === 'p');
    expect(typedSrc).toBeDefined();
    expect(typedSrc?.type).toBe('http_param');
  });

  it('axum-style extract::Path is also recognised', async () => {
    const code = `
use axum::extract::Path;
use std::process::Command;

async fn handler(Path(name): Path<String>) -> String {
    let _ = Command::new("sh").arg("-c").arg(format!("echo {}", name)).output();
    "ok".to_string()
}
`;
    const r = await analyze(code, 'g.rs', 'rust');
    const sources = r.taint?.sources ?? [];
    // axum bare `Path<String>` should match the typed-extractor regex
    // (RUST_EXTRACTOR_KIND accepts both bare and ::-prefixed forms).
    expect(sources.some(s => s.type === 'http_param')).toBe(true);
  });

  it('does NOT promote axum Extension<T> to a source (server-side state, not user input)', async () => {
    const code = `
use axum::Extension;
use std::sync::Arc;

struct AppState { db: String }

async fn handler(Extension(state): Extension<Arc<AppState>>) -> String {
    state.db.clone()
}
`;
    const r = await analyze(code, 'h.rs', 'rust');
    const sources = r.taint?.sources ?? [];
    // Extension is server-injected state, not user-controlled.
    expect(sources.some(s => s.variable === 'state' && s.type === 'http_param')).toBe(false);
  });
});
