/**
 * cognium-dev#735 (item 2): `r#return` must not count as a rejecting guard body.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { findRustLiteralEqualityGuardSanitizers } from '../../src/analysis/rust-literal-guard.js';

async function ci(code: string): Promise<number[]> {
  const r = await analyze(code, 'launcher.rs', 'rust', { speculativeParamSources: true });
  return (r.taint.flows ?? [])
    .filter((f) => f.sink_type === 'command_injection')
    .map((f) => f.sink_line)
    .sort((a, b) => a - b);
}

const LAUNCHER = `use std::process::Command;

pub fn launch(cmd: &str, extra: &str) -> Result<String, String> {
    if cmd != "uptime" && cmd != "whoami" {
        let r#return = 1; let _ = r#return;
    }
    let out = Command::new(cmd).output().map_err(|e| e.to_string())?;
    Ok(String::new())
}
`;

describe('cognium-dev#735 — Rust raw identifier is not a reject', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('r#return body: no sanitizer credit; command_injection reported', async () => {
    const sinks = findRustLiteralEqualityGuardSanitizers(LAUNCHER);
    expect(sinks.map((s) => s.line)).toEqual([]);
    expect(await ci(LAUNCHER)).toEqual([7]);
  });

  it('real return Err still credits the guard', async () => {
    const code = `use std::process::Command;

pub fn launch(cmd: &str) -> Result<String, String> {
    if cmd != "uptime" && cmd != "whoami" {
        return Err("no".into());
    }
    let out = Command::new(cmd).output().map_err(|e| e.to_string())?;
    Ok(String::new())
}
`;
    const sinks = findRustLiteralEqualityGuardSanitizers(code);
    expect(sinks.length).toBeGreaterThan(0);
    expect(await ci(code)).toEqual([]);
  });

  it('r#return plus real return still credits (real return wins)', async () => {
    const code = `use std::process::Command;

pub fn launch(cmd: &str) -> Result<String, String> {
    if cmd != "uptime" && cmd != "whoami" {
        let r#return = 1; return Err("no".into());
    }
    let out = Command::new(cmd).output().map_err(|e| e.to_string())?;
    Ok(String::new())
}
`;
    const sinks = findRustLiteralEqualityGuardSanitizers(code);
    expect(sinks.length).toBeGreaterThan(0);
    expect(await ci(code)).toEqual([]);
  });
});
