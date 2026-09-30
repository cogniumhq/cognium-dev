/**
 * #484 / #294 — two changes that are only safe together.
 *
 * 1. `matchesSinkPattern`'s bare-call branch built its expected tail with a
 *    DOT (`<class>.<method>`). Its motivating case was Python
 *    (`from urllib.request import urlopen`), which is dot-separated. Rust
 *    resolution stores the path with `::`, so
 *
 *        use serde_json::from_str;  from_str(&body)
 *          -> resolution.target = "serde_json::from_str"
 *
 *    never matched `{ method: 'from_str', class: 'serde_json' }`. The
 *    resolution was correct; the comparison could not see it.
 *
 * 2. Because of (1), the IMPORTED forms were only ever caught by the classless
 *    `from_str` / `from_slice` rows — which also matched every ordinary
 *    `u32::from_str` / `PublicKey::from_slice`, the #294 false positive. So
 *    dropping the classless rows alone opened a false negative across
 *    serde_json / serde_yaml / toml, and keeping them left the FP.
 *
 * With the separator normalised, the class-scoped rows cover the imported form
 * and the classless rows can go.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const deser = async (code: string) => {
  const r = await analyze(code, 'lib.rs', 'rust');
  return (r.taint?.sinks ?? []).filter(s => s.type === 'deserialization');
};

describe('#484 Rust `::` path separator in resolved sink targets', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['use serde_json::from_str', 'use serde_json::from_str;\npub fn p(b: String) { let v: serde_json::Value = from_str(&b).unwrap(); }'],
    ['use serde_json::{from_str, Value}', 'use serde_json::{from_str, Value};\npub fn p(b: String) { let v: Value = from_str(&b).unwrap(); }'],
    ['use serde_yaml::from_str', 'use serde_yaml::from_str;\npub fn p(b: String) { let v: serde_yaml::Value = from_str(&b).unwrap(); }'],
    ['use toml::from_str', 'use toml::from_str;\npub fn p(b: String) { let v: toml::Value = from_str(&b).unwrap(); }'],
    ['use serde_json::from_slice', 'use serde_json::from_slice;\npub fn p(b: &[u8]) { let v: serde_json::Value = from_slice(b).unwrap(); }'],
  ])('the imported form %s is a deserialization sink', async (_label, code) => {
    expect(await deser(code)).not.toHaveLength(0);
  });

  it('the path-qualified form still matches', async () => {
    expect(await deser('pub fn p(b: String) { let v: serde_json::Value = serde_json::from_str(&b).unwrap(); }')).not.toHaveLength(0);
  });

  it.each([
    ['u32::from_str', 'use std::str::FromStr;\npub fn p(s: &str) { let n = u32::from_str(s).unwrap(); }'],
    ['Url::from_str', 'pub fn p(s: &str) { let u = Url::from_str(s).unwrap(); }'],
    ['PublicKey::from_slice', 'pub fn p(b: &[u8]) { let k = PublicKey::from_slice(b).unwrap(); }'],
  ])('ordinary parsing %s is NOT a deserialization sink (#294)', async (_label, code) => {
    expect(await deser(code)).toHaveLength(0);
  });
});
