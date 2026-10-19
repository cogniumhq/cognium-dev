/**
 * cognium-dev #817 — ts-rust-parity quartet path_traversal FN (cross-file xfile shape).
 * Probe: controller reads actix Query; helper reaches a path_traversal-classified sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — Rust cross-file path_traversal (ts-rust-parity quartet)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `mod helper;
use helper::read_user_path;
use actix_web::web;
use std::collections::HashMap;

pub async fn handle(q: web::Query<HashMap<String, String>>) {
    let path = q.get("path").map(|s| s.as_str()).unwrap_or("");
    read_user_path(path);
}
`;

  const helperRead = `use std::fs;

pub fn read_user_path(path: &str) {
    let _ = fs::read_to_string(path);
}
`;

  it('cross-file http_param → helper fs::read_to_string path_traversal sink', async () => {
    const r = await analyzeProject([
      { code: helperRead, filePath: 'helper.rs', language: 'rust' },
      { code: controller, filePath: 'controller.rs', language: 'rust' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'path_traversal');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.rs' && p.sink.file === 'helper.rs',
    );
    expect(xfile, 'expected controller.rs → helper.rs path_traversal').toBeTruthy();
  });

  it('helper alone — no spurious path_traversal without tainted param', async () => {
    const r = await analyzeProject([{ code: helperRead, filePath: 'helper.rs', language: 'rust' }]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
    expect(flows).toHaveLength(0);
  });
});
