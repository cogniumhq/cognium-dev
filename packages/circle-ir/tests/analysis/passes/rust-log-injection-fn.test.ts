import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 56 — #182 Slice A: Rust `log::info!(...)` and the namespaced
 * log:: macro family (warn / error / debug / trace / log) are currently
 * missed because DEFAULT_SINKS registers bare `info!`/`warn!`/etc., but
 * the Rust macro extractor preserves the full path prefix in method_name
 * (`log::info!`). The bare entries only match the imported form
 * `use log::info; info!(...)`.
 *
 * Asserts sink detection (not flow): the engine's source→sink mapping
 * (canSourceReachSink) does not currently include `log_injection`, so
 * flows are never emitted for this sink type. The detector gap closed
 * here is purely the missing macro-name match.
 *
 * Recall locks: bare `info!(...)` (with `use log::info;`) and `println!`
 * sinks must keep being detected.
 */
describe('Sprint 56 — #182 Rust log_injection (namespaced log:: macros)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sinkMethods = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.sinks ?? []).filter(s => s.type === 'log_injection').map(s => s.method);

  it('FN — log::info!(...) is detected as log_injection sink', async () => {
    const code = `fn main() {
    log::info!("audit user={}", "alice");
}`;
    const r = await analyze(code, 'a.rs', 'rust');
    expect(sinkMethods(r)).toContain('log::info!');
  });

  it('FN — log::warn!/error!/debug!/trace! all detected as log_injection sinks', async () => {
    const code = `fn main() {
    log::warn!("w={}", "x");
    log::error!("e={}", "x");
    log::debug!("d={}", "x");
    log::trace!("t={}", "x");
}`;
    const r = await analyze(code, 'b.rs', 'rust');
    const methods = sinkMethods(r);
    expect(methods).toContain('log::warn!');
    expect(methods).toContain('log::error!');
    expect(methods).toContain('log::debug!');
    expect(methods).toContain('log::trace!');
  });

  it('recall — bare info!(...) (use log::info) is still detected', async () => {
    const code = `use log::info;
fn main() {
    info!("u={}", "x");
}`;
    const r = await analyze(code, 'c.rs', 'rust');
    expect(sinkMethods(r)).toContain('info!');
  });

  it('recall — println!(...) is still detected', async () => {
    const code = `fn main() {
    println!("u={}", "x");
}`;
    const r = await analyze(code, 'd.rs', 'rust');
    expect(sinkMethods(r)).toContain('println!');
  });
});
