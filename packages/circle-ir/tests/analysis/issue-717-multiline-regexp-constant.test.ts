/**
 * cognium-dev#717 — a constant `new RegExp(`…${CONST}…`)` pattern is exempt
 * from `redos` on a tainted subject (#681) even when the constructor call
 * spans several lines, as a formatter wraps a long statement.
 *
 * SAST regression fixture — the "fires" handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const FIELD = `const FIELD = "(?:[a-z0-9_-]*(?:token|secret|password)[a-z0-9_-]*|pass|cookie)";`;

const subject = `
export function run() {
  const raw = process.env.BEAM_TRANSCRIPT || "";
  return redactBlocks(raw);
}
`;

const wrap = (decl: string, ctor: string) => `${decl}

export function redactBlocks(text) {
${ctor}
  return text.split("\\n").filter((line) => blockLine.test(line));
}
${subject}`;

const SPLIT = (pattern: string) => `  const blockLine = new RegExp(
    ${pattern},
    "i",
  );`;
const ONE_LINE = (pattern: string) => `  const blockLine = new RegExp(${pattern}, "i");`;

const CONST_PATTERN = '`^(\\\\s*)(["\']?)(${FIELD})\\\\2\\\\s*:\\\\s*[|>]`';

async function redos(code: string) {
  const r = await analyze(code, 'redact_lines.js', 'javascript');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'redos');
}

describe('cognium-dev#717 — constant RegExp pattern across a line break', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('split-line call with a constant template pattern is clean', async () => {
    expect(await redos(wrap(FIELD, SPLIT(CONST_PATTERN)))).toHaveLength(0);
  });

  it('one-line form stays clean', async () => {
    expect(await redos(wrap(FIELD, ONE_LINE(CONST_PATTERN)))).toHaveLength(0);
  });

  it('split-line call with the pattern on the same line as the paren is clean', async () => {
    const ctor = `  const blockLine = new RegExp(${CONST_PATTERN},\n    "i");`;
    expect(await redos(wrap(FIELD, ctor))).toHaveLength(0);
  });

  it('split-line call with a comment between the paren and the pattern is clean', async () => {
    const ctor = `  const blockLine = new RegExp(\n    // block header\n    ${CONST_PATTERN},\n    "i",\n  );`;
    expect(await redos(wrap(FIELD, ctor))).toHaveLength(0);
  });

  it('still fires: split-line call with a tainted interpolation', async () => {
    const pattern = '`^(${FIELD})${process.env.EXTRA}\\\\s*:`';
    expect((await redos(wrap(FIELD, SPLIT(pattern)))).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: split-line call with a nested-quantifier constant', async () => {
    const decl = `const FIELD = "(a+)+$";`;
    expect((await redos(wrap(decl, SPLIT('`^${FIELD}`')))).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: one-line call with a nested-quantifier constant', async () => {
    const decl = `const FIELD = "(a+)+$";`;
    expect((await redos(wrap(decl, ONE_LINE('`^${FIELD}`')))).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: split-line call whose pattern is a tainted variable', async () => {
    const ctor = `  const blockLine = new RegExp(\n    text,\n    "i",\n  );`;
    expect((await redos(wrap(FIELD, ctor))).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: a later constant template must not exempt an earlier tainted constructor', async () => {
    const ctor = `  const first = new RegExp(\n    text,\n    "i",\n  );\n  const blockLine = new RegExp(\n    ${CONST_PATTERN},\n    "i",\n  );\n  first.test(text);`;
    expect((await redos(wrap(FIELD, ctor))).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: constant that is reassigned (let) in a split-line call', async () => {
    const decl = `let FIELD = "(?:token)";`;
    expect((await redos(wrap(decl, SPLIT(CONST_PATTERN)))).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: split-line call that concatenates the subject onto the template', async () => {
    const ctor = `  const blockLine = new RegExp(\n    ${CONST_PATTERN} + text,\n    "i",\n  );`;
    expect((await redos(wrap(FIELD, ctor))).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: one-line call that concatenates the subject onto the template', async () => {
    const ctor = `  const blockLine = new RegExp(${CONST_PATTERN} + text, "i");`;
    expect((await redos(wrap(FIELD, ctor))).length).toBeGreaterThanOrEqual(1);
  });
});
