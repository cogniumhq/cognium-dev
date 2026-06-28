import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 56 — #182 Slice C: Rust `format!("Set-Cookie: sid={}", v)` /
 * `write!(buf, "Set-Cookie: sid={}", v)` without `Secure` / `HttpOnly`
 * tokens must fire insecure-cookie. Pass currently lacks any Rust branch.
 *
 * TNs: format with `; Secure; HttpOnly` present → no finding;
 * unrelated `format!` → no finding.
 */
describe('Sprint 56 — #182 Rust insecure-cookie (format!/write!)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countInsecure = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.findings ?? []).filter(f => f.rule_id === 'insecure-cookie').length;

  it('FN — format!("Set-Cookie: ...") without Secure/HttpOnly must fire', async () => {
    const code = `fn build_cookie(sid: &str) -> String {
    format!("Set-Cookie: sid={}; Path=/", sid)
}`;
    const r = await analyze(code, 'a.rs', 'rust');
    expect(countInsecure(r)).toBeGreaterThanOrEqual(1);
  });

  it('FN — write!(buf, "Set-Cookie: ...") without Secure/HttpOnly must fire', async () => {
    const code = `use std::fmt::Write;
fn build_cookie(buf: &mut String, sid: &str) {
    write!(buf, "Set-Cookie: sid={}; Path=/", sid).unwrap();
}`;
    const r = await analyze(code, 'b.rs', 'rust');
    expect(countInsecure(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN — format!("Set-Cookie: ...; Secure; HttpOnly") must not fire', async () => {
    const code = `fn build_cookie(sid: &str) -> String {
    format!("Set-Cookie: sid={}; Path=/; Secure; HttpOnly", sid)
}`;
    const r = await analyze(code, 'c.rs', 'rust');
    expect(countInsecure(r)).toBe(0);
  });

  it('TN — unrelated format! must not fire', async () => {
    const code = `fn greet(name: &str) -> String {
    format!("hello {}", name)
}`;
    const r = await analyze(code, 'd.rs', 'rust');
    expect(countInsecure(r)).toBe(0);
  });
});
