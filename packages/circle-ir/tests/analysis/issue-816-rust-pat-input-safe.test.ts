/**
 * cognium-dev #816 — PAT-INPUT-01 Rust safe mirror (cve-intake-b).
 * Parse + finite range guards before actix `.body(...)`; recall on raw echo.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const xssFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);

const safeXferRoute = `use actix_web::{web, HttpResponse};

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

const safeXferWithToRoute = `use actix_web::{web, HttpResponse};

async fn xfer(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let to = q.get("to").cloned().unwrap_or_default();
    let amount_str = q.get("amount").map(|s| s.as_str()).unwrap_or("0");
    let amount: i32 = amount_str.parse().unwrap_or(0);
    const MAX: i32 = 1000;
    if amount <= 0 {
        return HttpResponse::BadRequest().finish();
    }
    if amount > MAX {
        return HttpResponse::BadRequest().finish();
    }
    HttpResponse::Ok().body(format!("xfer {} to {}", amount, to))
}
`;

const rawEchoRoute = `use actix_web::{web, HttpResponse};

async fn echo(q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let msg = q.get("msg").cloned().unwrap_or_default();
    HttpResponse::Ok().body(msg)
}
`;

describe('#816 PAT-INPUT-01 rust safe mirror', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('range-checked parse stays clean in format body', async () => {
    const ir = await analyze(safeXferRoute, 'pat_input_safe_mirror.rs', 'rust');
    expect(xssFlows(ir)).toEqual([]);
  });

  it('FQ-T3-S01 shape: bounded amount beside raw to stays clean (input_validation_safe.rs)', async () => {
    const ir = await analyze(safeXferWithToRoute, 'input_validation_safe.rs', 'rust');
    expect(xssFlows(ir)).toEqual([]);
  });

  it('recall: raw query in body still emits xss', async () => {
    const ir = await analyze(rawEchoRoute, 'pat_input_tp_mirror.rs', 'rust');
    expect(xssFlows(ir).length).toBeGreaterThan(0);
  });
});
