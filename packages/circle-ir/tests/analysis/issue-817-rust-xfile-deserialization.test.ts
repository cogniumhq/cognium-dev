/**
 * cognium-dev #817 — interop IL-57 rust env → json → deser FN (cross-file xfile shape).
 * Controller reads env + JSON; helper calls serde_yaml::from_str on the param.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — Rust cross-file deserialization (interop IL-57)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `use serde_json::Value;

mod helper;
use helper::run;

pub fn handle() {
    let user_blob = std::env::var("DATA").unwrap_or_default();
    let node: Value = serde_json::from_str(&user_blob).unwrap_or_default();
    let raw = node.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    run(raw);
}
`;

  const helper = `pub fn run(raw: &str) {
    let _cfg: serde_yaml::Value = serde_yaml::from_str(raw).unwrap_or_default();
}
`;

  it('cross-file env_input → helper deserialization sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.rs', language: 'rust' },
      { code: controller, filePath: 'controller.rs', language: 'rust' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'deserialization');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.rs' && p.sink.file === 'helper.rs',
    );
    expect(xfile, 'expected controller.rs → helper.rs deserialization').toBeTruthy();
  });

  it('helper alone — no spurious deserialization without tainted param', async () => {
    const r = await analyzeProject([{ code: helper, filePath: 'helper.rs', language: 'rust' }]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'deserialization');
    expect(flows).toHaveLength(0);
  });
});
