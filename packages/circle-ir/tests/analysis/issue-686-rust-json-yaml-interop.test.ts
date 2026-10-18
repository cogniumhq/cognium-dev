/**
 * cognium-dev #686 — Rust interop IL-57: env JSON → `Value::get` / `and_then` /
 * `as_str` chain must reach `serde_yaml::from_str` (deserialization).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const deserFlows = async (code: string, file = 'interop_env_json_to_deser.rs') => {
  const ir = await analyze(code, file, 'rust');
  return (ir.taint?.flows ?? []).filter(f => f.sink_type === 'deserialization');
};

beforeAll(async () => {
  await initAnalyzer();
});

describe('#686 Rust JSON node → optional string → yaml deser', () => {
  const vulnerable = `use std::env;

pub fn ingest() {
    let user_blob = env::var("DATA").unwrap_or_default();
    let node: serde_json::Value = serde_json::from_str(&user_blob).unwrap_or_default();
    let raw = node.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    let _cfg: serde_yaml::Value = serde_yaml::from_str(raw).unwrap_or_default();
}
`;

  it('reports deserialization when taint crosses get/and_then/as_str into serde_yaml', async () => {
    const flows = await deserFlows(vulnerable);
    expect(flows.length).toBe(1);
    expect(flows[0].sink_line).toBe(7);
    expect(flows[0].source_type).toBe('env_input');
  });

  it('stays clean when the yaml input is a literal', async () => {
    const safe = `pub fn ingest() {
    let raw = "name: ok";
    let _cfg: serde_yaml::Value = serde_yaml::from_str(raw).unwrap_or_default();
}
`;
    expect(await deserFlows(safe)).toHaveLength(0);
  });

  it('does not treat serde_json::from_str into Value as deserialization', async () => {
    const code = `use std::env;
pub fn ingest() {
    let user_blob = env::var("DATA").unwrap_or_default();
    let _node: serde_json::Value = serde_json::from_str(&user_blob).unwrap_or_default();
}
`;
    const ir = await analyze(code, 'json_only.rs', 'rust');
    const deserSinks = (ir.taint?.sinks ?? []).filter(s => s.type === 'deserialization');
    expect(deserSinks).toHaveLength(0);
  });
});
