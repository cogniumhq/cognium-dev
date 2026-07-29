/**
 * Tests for cognium-dev #267 — prompt-injection safety gate.
 *
 * circle-ir already fires `prompt_injection` (CWE-1427) when tainted input
 * reaches an LLM-client call (#248). The gate adds precision: it drops the
 * sink when the untrusted content is placed *safely* (role-separated
 * standalone user message, or delimiter-wrapped), while keeping genuine
 * flows (untrusted concatenated/interpolated into instructions, or in a
 * system/assistant role). This is the OWASP-LLM LLM01 TP/SAFE distinction
 * from the trust-recall oracle.
 *
 * Scope: Python + JS/TS, where the message structure is at the call site.
 * Go/Java builder-pattern coverage (request constructed in a separate
 * statement) and the Go struct-field taint gap are deeper follow-ups.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import {
  classifyPromptCall,
  scanValue,
  isDelimiterLiteral,
} from '../../../src/analysis/passes/prompt-injection-safety-gate-pass.js';

const PY = (msgBody: string, pre = '') => `from flask import request
from openai import OpenAI
client = OpenAI()
def h():
    user = request.args.get("q")
${pre}    client.chat.completions.create(model="m", messages=[${msgBody}])`;

const JS = (msgBody: string, pre = '') => `const OpenAI = require('openai');
const client = new OpenAI();
app.get('/', async (req) => {
  const user = req.query.q;
${pre}  await client.chat.completions.create({ model: 'm', messages: [${msgBody}] });
});`;

const firesPromptInjection = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).some(f => f.sink_type === 'prompt_injection');

describe('cognium-dev #267 — prompt-injection safety gate', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ── True positives: untrusted mixed into instructions / system role ────

  it('Python — untrusted concatenated into content fires (TP)', async () => {
    const r = await analyze(PY(`{"role":"user","content":"Follow policy.\\n" + user}`), 'p.py', 'python');
    expect(firesPromptInjection(r)).toBe(true);
  });

  it('Python — untrusted in a system role fires (TP)', async () => {
    const r = await analyze(PY(`{"role":"system","content":user},{"role":"user","content":"hi"}`), 'p.py', 'python');
    expect(firesPromptInjection(r)).toBe(true);
  });

  it('Python — untrusted interpolated into an instruction f-string fires (TP)', async () => {
    const r = await analyze(PY(`{"role":"user","content":f"Follow policy. {user}"}`), 'p.py', 'python');
    expect(firesPromptInjection(r)).toBe(true);
  });

  it('JS — untrusted concatenated into content fires (TP)', async () => {
    const r = await analyze(JS(`{ role: 'user', content: 'Follow policy.\\n' + user }`), 'p.js', 'javascript');
    expect(firesPromptInjection(r)).toBe(true);
  });

  it('JS — untrusted in an instruction template literal fires (TP)', async () => {
    const r = await analyze(JS(`{ role: 'user', content: \`Follow policy. \${user}\` }`), 'p.js', 'javascript');
    expect(firesPromptInjection(r)).toBe(true);
  });

  // ── Safe mirrors: role-separated / delimiter-wrapped → suppressed ───────

  it('Python — role-separated standalone user content is clean (SAFE)', async () => {
    const r = await analyze(PY(`{"role":"system","content":"Follow policy."},{"role":"user","content":user}`), 'p.py', 'python');
    expect(firesPromptInjection(r)).toBe(false);
  });

  it('Python — delimiter-wrapped (via var) is clean (SAFE)', async () => {
    const r = await analyze(
      PY(`{"role":"user","content":wrapped}`, `    wrapped = "<user_question>" + user + "</user_question>"\n`),
      'p.py', 'python',
    );
    expect(firesPromptInjection(r)).toBe(false);
  });

  it('Python — delimiter-wrapped (inline) is clean (SAFE)', async () => {
    const r = await analyze(PY(`{"role":"user","content":"<user_question>" + user + "</user_question>"}`), 'p.py', 'python');
    expect(firesPromptInjection(r)).toBe(false);
  });

  it('JS — role-separated standalone user content is clean (SAFE)', async () => {
    const r = await analyze(JS(`{ role: 'system', content: 'Follow policy.' }, { role: 'user', content: user }`), 'p.js', 'javascript');
    expect(firesPromptInjection(r)).toBe(false);
  });

  it('JS — delimiter-wrapped (via var) is clean (SAFE)', async () => {
    const r = await analyze(
      JS(`{ role: 'user', content: w }`, `  const w = '<user_question>' + user + '</user_question>';\n`),
      'p.js', 'javascript',
    );
    expect(firesPromptInjection(r)).toBe(false);
  });

  // ── Classifier units (robustness of the structural analysis) ──────────

  it('classifyPromptCall distinguishes concat/system (unsafe) from role-sep/delimiter (safe)', () => {
    const L = (s: string) => [s];
    expect(classifyPromptCall(`create(messages=[{"role":"user","content":"instr " + x}])`, L(''))).toBe('unsafe');
    expect(classifyPromptCall(`create(messages=[{"role":"system","content":x}])`, L(''))).toBe('unsafe');
    expect(classifyPromptCall(`create(messages=[{"role":"user","content":x}])`, L(''))).toBe('safe');
    expect(classifyPromptCall(`create(messages=[{"role":"user","content":"<q>" + x + "</q>"}])`, L(''))).toBe('safe');
    // no dynamic content → unknown (kept)
    expect(classifyPromptCall(`create(messages=[{"role":"user","content":"static"}])`, L(''))).toBe('unknown');
  });

  it('scanValue does not truncate on } inside f-string / template interpolation', () => {
    expect(scanValue(`content:f"a {user}"}`, 'content:'.length)).toBe('f"a {user}"');
    expect(scanValue('content:`a ${user}`}', 'content:'.length)).toBe('`a ${user}`');
  });

  it('isDelimiterLiteral recognizes boundary markers but not instruction text', () => {
    expect(isDelimiterLiteral('<user_question>')).toBe(true);
    expect(isDelimiterLiteral('</user_question>')).toBe(true);
    expect(isDelimiterLiteral('[data]')).toBe(true);
    expect(isDelimiterLiteral('```')).toBe(true);
    expect(isDelimiterLiteral('Follow policy.')).toBe(false);
  });
});
