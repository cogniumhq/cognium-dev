/**
 * Dogfood 2026-11-03 (cognium-ai circle-ir-ai agents/mastra/swarm.ts): a Node
 * write stream ended with `writeStream!.end(() => resolve())` was reported as a
 * high resource leak ("never closed"). `Writable.end()` releases the stream, and
 * the receiver text carries the TypeScript non-null marker `!`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const highLeaks = async (code: string, file: string, lang: 'typescript' | 'javascript') =>
  ((await analyze(code, file, lang)).findings ?? [])
    .filter(f => f.rule_id === 'resource-leak' && f.severity === 'high')
    .map(f => f.line);

describe('resource-leak: a Node stream is released by end()', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('ws!.end() inside a promise closes a nullable stream', async () => {
    const code = `import * as fs from 'fs';
export async function run(out: string | undefined): Promise<void> {
  let writeStream: fs.WriteStream | null = null;
  if (out) {
    writeStream = fs.createWriteStream(out, { flags: 'w' });
  }
  writeStream?.write('x');
  if (writeStream) {
    await new Promise<void>((resolve) => writeStream!.end(() => resolve()));
  }
}`;
    expect(await highLeaks(code, 'swarm.ts', 'typescript')).toEqual([]);
  });

  it('ws.end() and ws?.end() close the stream (TS and JS)', async () => {
    const ts = `import * as fs from 'fs';
export function a(out: string): void {
  const ws = fs.createWriteStream(out);
  ws.write('x');
  ws.end();
}
export function b(out: string): void {
  const ws: fs.WriteStream | undefined = fs.createWriteStream(out);
  ws?.end();
}`;
    expect(await highLeaks(ts, 'a.ts', 'typescript')).toEqual([]);
    const js = `const fs = require('fs');
function a(out) {
  const ws = fs.createWriteStream(out);
  ws.write('x');
  ws.end();
}
module.exports = { a };`;
    expect(await highLeaks(js, 'a.js', 'javascript')).toEqual([]);
  });

  it('still reports a stream that is written and never ended', async () => {
    const code = `import * as fs from 'fs';
export function leaky(out: string): void {
  const ws = fs.createWriteStream(out);
  ws.write('x');
}`;
    expect(await highLeaks(code, 'a.ts', 'typescript')).toEqual([3]);
  });

  it('still reports a stream whose end() is on a different variable', async () => {
    const code = `import * as fs from 'fs';
export function other(out: string, log: fs.WriteStream): void {
  const ws = fs.createWriteStream(out);
  ws.write('x');
  log.end();
}`;
    expect(await highLeaks(code, 'a.ts', 'typescript')).toEqual([3]);
  });
});
