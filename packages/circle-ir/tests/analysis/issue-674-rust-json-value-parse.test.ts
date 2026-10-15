/**
 * #674 — `serde_json::from_str` / `from_slice` / `from_reader` that parses
 * into `serde_json::Value` is a data-only parse, not CWE-502. A typed target
 * (`let c: Config = serde_json::from_str(..)`) is still reported, and so is
 * every other format (`serde_yaml`, `toml`, ...) regardless of the target type.
 *
 * The response-body `xss` finding on `HttpResponse::Ok().body(..)` is a
 * separate question and is intentionally unchanged here (keeps firing).
 *
 * Fixtures use renamed handlers, variables and types on purpose.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const run = async (code: string) => analyze(code, 'handler.rs', 'rust');
const deserLines = async (code: string) =>
  ((await run(code)).taint?.sinks ?? []).filter((s) => s.type === 'deserialization').map((s) => s.line);

describe('#674 serde_json parse into Value is not a deserialization sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['annotated, path-qualified type',
      'pub fn load(raw: String) {\n    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();\n}'],
    ['annotated, imported type',
      'use serde_json::Value;\npub fn load(raw: String) {\n    let doc: Value = serde_json::from_str(&raw).unwrap();\n}'],
    ['annotated mut binding',
      'pub fn load(raw: String) {\n    let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();\n}'],
    ['from_slice into Value',
      'pub fn load(raw: &[u8]) {\n    let doc: serde_json::Value = serde_json::from_slice(raw).unwrap();\n}'],
    ['from_reader into Value',
      'pub fn load(rd: impl std::io::Read) {\n    let doc: serde_json::Value = serde_json::from_reader(rd).unwrap();\n}'],
    ['imported call form into Value',
      'use serde_json::from_str;\npub fn load(raw: String) {\n    let doc: serde_json::Value = from_str(&raw).unwrap();\n}'],
    ['wrapped let statement',
      'pub fn load(raw: String) {\n    let doc: serde_json::Value =\n        serde_json::from_str(&raw).unwrap();\n}'],
  ])('%s -> no deserialization sink', async (_label, code) => {
    expect(await deserLines(code)).toEqual([]);
  });

  it('the issue fixture: safe side has no deserialization, response body xss unchanged', async () => {
    const safe = await run(`use actix_web::{web, HttpResponse};
pub async fn restore_view(payload: String) -> HttpResponse {
    let v: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
    HttpResponse::Ok().body(v.to_string())
}`);
    const types = (safe.taint?.sinks ?? []).map((s) => s.type);
    expect(types).not.toContain('deserialization');
    expect(types).toContain('xss');
  });

  // ---- negatives: these must keep firing -----------------------------------

  it.each([
    ['serde_yaml into Value',
      'pub fn load(raw: String) {\n    let doc: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap_or_default();\n}'],
    ['toml into Value',
      'pub fn load(raw: String) {\n    let doc: toml::Value = toml::from_str(&raw).unwrap();\n}'],
    ['serde_json into a typed struct',
      'pub fn load(raw: String) {\n    let cfg: Settings = serde_json::from_str(&raw).unwrap();\n}'],
    ['serde_json with no declared type',
      'pub fn load(raw: String) {\n    let cfg = serde_json::from_str(&raw).unwrap();\n}'],
    ['serde_json into a type whose name merely ends in Value',
      'pub fn load(raw: String) {\n    let cfg: ConfigValue = serde_json::from_str(&raw).unwrap();\n}'],
    ['serde_json from_slice typed',
      'pub fn load(raw: &[u8]) {\n    let cfg: Settings = serde_json::from_slice(raw).unwrap();\n}'],
  ])('%s -> still a deserialization sink', async (_label, code) => {
    expect(await deserLines(code)).toEqual([2]);
  });

  it('the issue positive control: serde_yaml::from_str into Value still fires', async () => {
    const tp = await run(`use actix_web::{web, HttpResponse};
pub async fn restore_view(payload: String) -> HttpResponse {
    let v: serde_json::Value = serde_yaml::from_str(&payload).unwrap_or_default();
    HttpResponse::Ok().body(v.to_string())
}`);
    const sinks = tp.taint?.sinks ?? [];
    expect(sinks.some((s) => s.type === 'deserialization' && s.line === 3)).toBe(true);
    expect(sinks.some((s) => s.type === 'xss')).toBe(true);
  });

  it('a Value parse next to a typed parse only drops the Value one', async () => {
    const lines = await deserLines(`pub fn load(raw: String) {
    let a: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let b: Settings = serde_json::from_str(&raw).unwrap();
}`);
    expect(lines).toEqual([3]);
  });
});
