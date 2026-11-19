/**
 * cognium-dev #1245 — flow-quartet tier-1 rust format_string FN.
 * Manifest: rust-vuln-demo/.../format_string/v01_baseline_tp.rs
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const tpRoute = `use actix_web::{web, HttpResponse};

pub async fn greet(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let pat = q.get("pat").cloned().unwrap_or_else(|| "{}".into());
    HttpResponse::Ok().body(format!("{}", pat))
}
`;

const formatFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter(
    (f) => f.sink_type === 'format_string' && !f.sanitized,
  );

describe('#1245 flow-quartet rust format_string', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('emits flow-backed format_string on actix body(format!(...)) TP mirror', async () => {
    const ir = await analyze(tpRoute, 'v01_baseline_tp.rs', 'rust');
    expect(formatFlows(ir).length).toBeGreaterThanOrEqual(1);
  });

  it('range-checked PAT-INPUT safe mirror stays clean (regression)', async () => {
    const safe = `use actix_web::{web, HttpResponse};

async fn xfer(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let amount_str = q.get("amount").map(|s| s.as_str()).unwrap_or("0");
    let amount: i32 = amount_str.parse().unwrap_or(0);
    const MAX: i32 = 1000;
    if amount <= 0 {
        return HttpResponse::BadRequest().finish();
    }
    if amount > MAX {
        return HttpResponse::BadRequest().finish();
    }
    HttpResponse::Ok().body(format!("xfer {}", amount))
}
`;
    const ir = await analyze(safe, 'pat_input_safe.rs', 'rust');
    expect(formatFlows(ir)).toEqual([]);
  });
});