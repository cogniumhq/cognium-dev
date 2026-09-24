import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #294 (part 1) — FP: Rust `format!` reported as a format-string
 * vulnerability (CWE-134).
 *
 * Rust's `format!` takes its template as a compile-time string literal;
 * interpolated values are arguments, never parsed as format directives. A
 * non-literal template does not compile, so CWE-134 (attacker-controlled
 * format string) is not expressible with `format!`. Interpolating data into
 * `format!` is the ordinary, safe way to build a string in Rust.
 *
 * Fix: drop `format!` as a `format_string` sink in the Rust plugin.
 *
 * (Parts 2 and 3 of #294 — serde_json deserialization and XSS-on-response-body
 * — are intentionally NOT addressed here: the serde_json sinks are locked by
 * an explicit plugin test and relate to planned work #261, and part 3 is a
 * separate XSS-context question.)
 */
describe('#294 part 1 — Rust format! is not a format_string sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('SAFE: format!("...literal...", user, amount) emits no format_string sink', async () => {
    const code = `pub fn render(user: &str, amount: i64) -> Result<String, String> {
    if amount < 0 { return Err("amount must be non-negative".into()); }
    Ok(format!("Hi {}, your balance changed by {} credits.", user, amount))
}`;
    const ir = await analyze(code, 'benign_template_fill.rs', 'rust');
    expect(ir.taint.sinks.filter(s => s.type === 'format_string')).toHaveLength(0);
  });

  it('CONTROL: Java String.format still emits a format_string sink (drop is Rust-scoped)', async () => {
    const code = [
      'public class C {',
      '  String h(String fmt, Object a) {',
      '    return String.format(fmt, a);',
      '  }',
      '}',
    ].join('\n');
    const ir = await analyze(code, 'C.java', 'java');
    expect(ir.taint.sinks.some(s => s.type === 'format_string')).toBe(true);
  });
});

/**
 * #294 (part 2, split) — the classless `from_str` / `from_slice`
 * deserialization rows matched every `T::from_str` / `from_slice`: ordinary
 * `FromStr` / byte parsing (`u32::from_str`, `Url::from_str`,
 * `PublicKey::from_slice`) was reported as CWE-502. Those rows are removed.
 * The class-scoped serde_json / serde_yaml / bincode / toml / ron sinks are
 * kept (owner decision 2026-09-24: typed serde_json is a separate labelling
 * question, and CWE-Bench-Rust RustTest00016 labels it CWE-502).
 */
describe('#294 part 2 — generic FromStr parsing is not a deserialization sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const deserAt = async (code: string) => {
    const ir = await analyze(code, 'lib.rs', 'rust');
    return ir.taint.sinks.filter((s) => s.type === 'deserialization').map((s) => s.line);
  };

  it('u32::from_str / Url::from_str / PublicKey::from_slice are not deserialization sinks', async () => {
    expect(await deserAt(`use std::str::FromStr;
pub fn parse(s: &str, b: &[u8]) {
    let n = u32::from_str(s).unwrap();
    let u = Url::from_str(s).unwrap();
    let k = PublicKey::from_slice(b).unwrap();
}`)).toEqual([]);
  });

  it('serde_json::from_str stays a deserialization sink (class-scoped row kept)', async () => {
    expect(await deserAt(`pub fn parse(body: String) {
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
}`)).toEqual([2]);
  });

  it('serde_yaml::from_str stays a deserialization sink', async () => {
    expect(await deserAt(`pub fn parse(body: String) {
    let v: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
}`)).toEqual([2]);
  });
});
