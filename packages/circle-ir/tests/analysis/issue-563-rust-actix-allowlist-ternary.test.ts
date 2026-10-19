/**
 * cognium-dev #563 — Rust actix `.body(x)` safe mirror: allowlist ternary
 * assigns either a membership-checked param or a constant default.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

async function xssLines(code: string): Promise<number[]> {
  const r = await analyze(code, 'theme_page.rs', 'rust');
  return (r.taint.flows ?? [])
    .filter((f) => f.sink_type === 'xss')
    .map((f) => f.sink_line)
    .sort((a, b) => a - b);
}

const safeTernary = `use actix_web::{web, HttpResponse};

const THEMES: &[&str] = &["light", "dark"];

async fn show(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let theme = q.get("theme").cloned().unwrap_or_default();
    let body = if THEMES.contains(&theme.as_str()) {
        theme
    } else {
        "default".to_string()
    };
    HttpResponse::Ok().body(body)
}
`;

const tpDirect = `use actix_web::{web, HttpResponse};

async fn show(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let theme = q.get("theme").cloned().unwrap_or_default();
    HttpResponse::Ok().body(theme)
}
`;

const unsafeTernary = `use actix_web::{web, HttpResponse};

async fn show(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let theme = q.get("theme").cloned().unwrap_or_default();
    let other = q.get("other").cloned().unwrap_or_default();
    let body = if theme == "light" || theme == "dark" {
        other
    } else {
        "default".to_string()
    };
    HttpResponse::Ok().body(body)
}
`;

describe('#563 Rust allowlist ternary body', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('safe: membership-checked ternary stays clean on .body(body)', async () => {
    expect(await xssLines(safeTernary)).toEqual([]);
  });

  it('tp: direct .body(theme) still reports', async () => {
    expect((await xssLines(tpDirect)).length).toBeGreaterThan(0);
  });

  it('unsafe ternary: non-guarded arm in then branch still reports', async () => {
    expect((await xssLines(unsafeTernary)).length).toBeGreaterThan(0);
  });
});
