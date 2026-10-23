/**
 * cognium-dev #897 — invalid ZIP local header still returns caller bytes.
 * Fixtures: coggiyadmin/javascript-vuln-demo @ d6f3025 intake/zip_header_failopen_*.js
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const inputValidationFindings = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'input_validation');

const tpFixture = `/**
 * TP — an invalid ZIP local header still returns caller-controlled bytes (CWE-20).
 * CVE-2026-106070 class: ZipFile returns a prefix after failed header validation.
 */
'use strict';

function readLocal(buf) {
  const sigOk = buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
  if (!sigOk) return Buffer.from(buf.subarray(0, Math.min(buf.length, 16))); // SINK CWE-20
  return Buffer.alloc(0);
}

module.exports = { readLocal };
`;

const safeFixture = `/**
 * Safe mirror — invalid header fails closed.
 */
'use strict';

function readLocal(buf) {
  const sigOk = buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
  if (!sigOk) throw new Error('invalid zip header');
  return Buffer.alloc(0);
}

module.exports = { readLocal };
`;

describe('#897 zip_header_failopen input_validation', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP: invalid header returns buf.subarray (input_validation)', async () => {
    const r = await analyze(tpFixture, 'zip_header_failopen_tp.js', 'javascript');
    expect(inputValidationFindings(r).length).toBeGreaterThan(0);
  });

  it('safe: invalid header throws — stays clean', async () => {
    const r = await analyze(safeFixture, 'zip_header_failopen_safe.js', 'javascript');
    expect(inputValidationFindings(r)).toHaveLength(0);
  });
});
