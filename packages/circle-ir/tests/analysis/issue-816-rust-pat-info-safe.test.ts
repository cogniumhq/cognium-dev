/**
 * cognium-dev #816 — PAT-INFO-01 Rust safe mirror (cve-intake-b / coggiyadmin).
 * Safe shape echoes only query params in JSON; TP still leaks env::var.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const infoFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter(
    (f) =>
      !f.sanitized &&
      (f.sink_type === 'xss' || f.sink_type === 'external_taint_escape'),
  );

const safeMirror = `use actix_web::{web, HttpResponse};

pub async fn info_disclosure_safe(req: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let q = req.get("q").cloned().unwrap_or_default();
    HttpResponse::Ok().body(format!(r#"{{"status":"ok","q":"{q}"}}"#))
}
`;

const tpMirror = `use actix_web::{web, HttpResponse};
use std::env;

pub async fn info_disclosure_tp(req: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let token = env::var("API_TOKEN").unwrap_or_default();
    let q = req.get("q").cloned().unwrap_or_default();
    HttpResponse::Ok().body(format!(r#"{{"token":"{token}","q":"{q}"}}"#))
}
`;

describe('#816 PAT-INFO-01 rust safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('query-only JSON body stays clean (info_disclosure family sinks)', async () => {
    const ir = await analyze(safeMirror, 'info_disclosure_safe.rs', 'rust');
    expect(infoFlows(ir)).toEqual([]);
  });

  it('recall: env token in response body still emits a flow', async () => {
    const ir = await analyze(tpMirror, 'info_disclosure_tp.rs', 'rust');
    expect(infoFlows(ir).length).toBeGreaterThan(0);
  });
});
