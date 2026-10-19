/**
 * cognium-dev #817 — ts-rust-parity quartet format_string FN (cross-file xfile shape).
 * Probe: controller reads actix Query; helper reaches a format_string-classified sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — Rust cross-file format_string (ts-rust-parity quartet)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `mod helper;
use helper::emit;
use actix_web::web;
use std::collections::HashMap;

pub async fn handle(q: web::Query<HashMap<String, String>>) {
    let fmt = q.get("fmt").map(|s| s.as_str()).unwrap_or("");
    emit(fmt);
}
`;

  const helperPrintf = `use std::ffi::CString;

extern "C" {
    fn printf(format: *const i8, ...) -> i32;
}

pub fn emit(fmt: &str) {
    let c = CString::new(fmt).unwrap();
    unsafe {
        printf(c.as_ptr());
    }
}
`;

  it('cross-file http_param → helper libc printf format_string sink', async () => {
    const r = await analyzeProject([
      { code: helperPrintf, filePath: 'helper.rs', language: 'rust' },
      { code: controller, filePath: 'controller.rs', language: 'rust' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'format_string');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.rs' && p.sink.file === 'helper.rs',
    );
    expect(xfile, 'expected controller.rs → helper.rs format_string').toBeTruthy();
  });

  it('helper alone — no spurious format_string without tainted param', async () => {
    const r = await analyzeProject([{ code: helperPrintf, filePath: 'helper.rs', language: 'rust' }]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'format_string');
    expect(flows).toHaveLength(0);
  });
});
