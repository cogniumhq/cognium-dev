/**
 * Tests for cognium-dev #146 — Rust & TypeScript cross-file taint.
 *
 * Extends closed #106 (cross-file py/js/java/go) to the two frontends that
 * were blocked upstream at the time (#67 TS parse, #82 Rust taint). At
 * HEAD, TypeScript cross-file taint already works; Rust was the remaining
 * gap and is fixed by the `collectTaintReachableVars` DFG-derived-variable
 * expansion of the cross-file connectivity gate in `cross-file.ts`.
 *
 * Shape (per #106 methodology): source in the controller, sink in an
 * imported helper. The helper is blank when scanned alone (its sink fires
 * only on a tainted param), so a `controller + helper` taint_path requires
 * genuine cross-file propagation.
 *
 * Soundness: a value rebound through a cross-file call (potential
 * sanitizer boundary) must NOT connect via this coarse pass — that is the
 * sanitizer-aware `findInterproceduralTaintPaths`' job. Locked by the
 * negative control below and by the pre-existing Java wrapper-sanitizer
 * control in `project-graph.test.ts`.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #146 — Rust & TypeScript cross-file taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const xfileTaintTo = (
    r: Awaited<ReturnType<typeof analyzeProject>>,
    sinkFile: string,
    sinkType: string,
  ) =>
    (r.taint_paths ?? []).some(
      p => p.source.type === 'http_param' &&
           p.sink.file === sinkFile &&
           p.sink.type === sinkType,
    );

  // ── Rust ──────────────────────────────────────────────────────────────

  const rustController = `mod helper;
use helper::run;
use actix_web::web;
use std::collections::HashMap;
pub async fn handle(q: web::Query<HashMap<String,String>>) {
    let v = q.get("v").unwrap();
    run(v);
}`;

  it('Rust — controller source → helper command_injection sink (cross-file)', async () => {
    const helper = `use std::process::Command;
pub fn run(arg: &str) { Command::new(arg).spawn().unwrap(); }`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.rs', language: 'rust' },
      { code: rustController, filePath: 'controller.rs', language: 'rust' },
    ]);
    expect(xfileTaintTo(r, 'helper.rs', 'command_injection')).toBe(true);
  });

  it('Rust — Command.output() is command_injection only, not a spurious xss (#146)', async () => {
    // `.output()` matched the classless Java template-output xss sink, so the
    // cmdi cross-file path was mislabeled xss. Now Rust is excluded from it.
    const helper = `use std::process::Command;
pub fn run(arg: &str) { Command::new("sh").arg("-c").arg(arg).output().unwrap(); }`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.rs', language: 'rust' },
      { code: rustController, filePath: 'controller.rs', language: 'rust' },
    ]);
    expect(xfileTaintTo(r, 'helper.rs', 'command_injection')).toBe(true);
    expect(xfileTaintTo(r, 'helper.rs', 'xss')).toBe(false);
  });

  it('Rust — controller source → helper path_traversal sink (cross-file)', async () => {
    const helper = `use std::fs;
pub fn run(arg: &str) { let _ = fs::read_to_string(arg); }`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.rs', language: 'rust' },
      { code: rustController, filePath: 'controller.rs', language: 'rust' },
    ]);
    expect(xfileTaintTo(r, 'helper.rs', 'path_traversal')).toBe(true);
  });

  it('Rust — controller source → helper sql_injection sink (cross-file)', async () => {
    const helper = `pub fn run(arg: &str, client: &mut postgres::Client) {
    let q = format!("SELECT * FROM t WHERE x = '{}'", arg);
    client.query(&q, &[]).unwrap();
}`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.rs', language: 'rust' },
      { code: rustController, filePath: 'controller.rs', language: 'rust' },
    ]);
    expect(xfileTaintTo(r, 'helper.rs', 'sql_injection')).toBe(true);
  });

  it('Rust soundness — value rebound through a cross-file call does NOT leak', async () => {
    // `safe` is produced by a cross-file call (`sanitize(...)`), so the
    // coarse connectivity gate must not follow raw → safe → run(safe).
    // (Whether `sanitize` truly sanitizes is the interprocedural pass's
    // determination; the coarse pass stays conservative.)
    const helper = `use std::process::Command;
pub fn run(arg: &str) { Command::new(arg).spawn().unwrap(); }`;
    const sanitizer = `pub fn sanitize(s: &str) -> String { s.replace("/", "") }`;
    const controller = `mod helper;
mod san;
use helper::run;
use san::sanitize;
use actix_web::web;
use std::collections::HashMap;
pub async fn handle(q: web::Query<HashMap<String,String>>) {
    let raw = q.get("v").unwrap();
    let safe = sanitize(raw);
    run(&safe);
}`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.rs', language: 'rust' },
      { code: sanitizer, filePath: 'san.rs', language: 'rust' },
      { code: controller, filePath: 'controller.rs', language: 'rust' },
    ]);
    // No coarse cross-file taint_path from the http_param source directly
    // into the helper sink (the value crossed a cross-file call boundary).
    const direct = (r.taint_paths ?? []).filter(
      p => p.source.type === 'http_param' &&
           p.sink.file === 'helper.rs' &&
           p.source.file === 'controller.rs',
    );
    expect(direct).toHaveLength(0);
  });

  // ── TypeScript (already worked at HEAD; locked here) ─────────────────

  const tsController = (v: string) => `import { run } from './helper';
import express from 'express';
export function handle(req: express.Request): void {
  const ${v} = req.query.${v} as string;
  run(${v});
}`;

  it('TypeScript — controller source → helper command_injection sink', async () => {
    const helper = `import { exec } from 'child_process';
export function run(arg: string): void { exec(arg); }`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.ts', language: 'typescript' },
      { code: tsController('cmd'), filePath: 'controller.ts', language: 'typescript' },
    ]);
    expect(xfileTaintTo(r, 'helper.ts', 'command_injection')).toBe(true);
  });

  it('TypeScript — controller source → helper sql_injection sink', async () => {
    const helper = `import { Pool } from 'pg';
const pool = new Pool();
export function run(arg: string): void { pool.query("SELECT * FROM t WHERE x = '" + arg + "'"); }`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.ts', language: 'typescript' },
      { code: tsController('v'), filePath: 'controller.ts', language: 'typescript' },
    ]);
    expect(xfileTaintTo(r, 'helper.ts', 'sql_injection')).toBe(true);
  });

  it('TypeScript — controller source → helper ssrf sink', async () => {
    const helper = `import fetch from 'node-fetch';
export function run(arg: string): void { fetch(arg); }`;
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.ts', language: 'typescript' },
      { code: tsController('u'), filePath: 'controller.ts', language: 'typescript' },
    ]);
    expect(xfileTaintTo(r, 'helper.ts', 'ssrf')).toBe(true);
  });
});
