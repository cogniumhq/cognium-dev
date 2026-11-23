/**
 * cognium-dev #1150 — Rust interop IL-57: parameter → serde_json → chain → serde_yaml.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const TP = `pub fn load(user_blob: &str) {
    let node: serde_json::Value = serde_json::from_str(user_blob).unwrap_or_default();
    let raw = node.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    let _: serde_json::Value = serde_yaml::from_str(raw).unwrap_or_default();
}
`;

const SAFE = `pub fn load() {
    let _: serde_json::Value = serde_json::from_str("{\"ok\":true}").unwrap_or_default();
}
`;

describe('#1150 Rust JSON param → yaml deserialization (interop IL-57)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports deserialization without speculativeParamSources', async () => {
    const ir = await analyze(TP, 'interop_env_json_to_deser.rs', 'rust');
    const flows = (ir.taint?.flows ?? []).filter(f => f.sink_type === 'deserialization');
    expect(flows.length).toBeGreaterThanOrEqual(1);
    expect(flows[0].sink_line).toBe(4);
    expect(flows[0].source_type).toBe('interprocedural_param');
  });

  it('constant-only safe mirror stays clean', async () => {
    const ir = await analyze(SAFE, 'safe_interop_env_json_to_deser.rs', 'rust');
    expect((ir.taint?.flows ?? []).filter(f => f.sink_type === 'deserialization')).toHaveLength(0);
  });
});
