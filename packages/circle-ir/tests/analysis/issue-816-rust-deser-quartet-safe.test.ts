/**
 * cognium-dev #816 — ts-rust-parity quartet tier-1 `deserialization` / rust safe
 * mirror (`rust-vuln-demo` v01_baseline_safe shape). `serde_json::from_str` into
 * `Value` must stay clean; `serde_yaml::from_str` recall on the TP twin.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const deserFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'deserialization' && !f.sanitized);

const safeMirror = `use actix_web::HttpResponse;

pub async fn restore_safe(body: String) -> HttpResponse {
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    HttpResponse::Ok().body(v.to_string())
}
`;

const tpMirror = `use actix_web::HttpResponse;

pub async fn restore(body: String) -> HttpResponse {
    let v: serde_json::Value = serde_yaml::from_str(&body).unwrap_or_default();
    HttpResponse::Ok().body(v.to_string())
}
`;

describe('#816 rust quartet deserialization safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('serde_json::from_str into Value stays clean for deserialization', async () => {
    const ir = await analyze(safeMirror, 'v01_baseline_safe.rs', 'rust');
    expect(deserFlows(ir)).toEqual([]);
  });

  it('recall: serde_yaml::from_str on body still emits deserialization', async () => {
    const ir = await analyze(tpMirror, 'v01_baseline_tp.rs', 'rust');
    expect(deserFlows(ir).length).toBeGreaterThan(0);
  });
});
