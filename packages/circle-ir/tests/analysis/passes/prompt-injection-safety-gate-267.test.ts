/**
 * Tests for cognium-dev #267 — prompt-injection safety gate.
 *
 * circle-ir fires `prompt_injection` (CWE-1427) when tainted input reaches
 * an LLM-client call (#248). The gate adds precision: it drops the sink
 * when the untrusted content is *delimiter-wrapped* (enclosed in matched
 * boundary markers), the OWASP-LLM LLM01 safe-mitigation shape, while
 * keeping genuine flows (untrusted concatenated/interpolated into
 * instructions, or in a system/assistant role).
 *
 * Scope decision: role separation alone is NOT a sanitizer — `{role:"user",
 * content: untrusted}` still fires, matching #248's must-fire contract.
 * Only affirmative delimiter-wrapping suppresses. Builder-pattern aware for
 * Go/Java (request built in a prior statement).
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import {
  classifyPromptCall,
  classifyPromptSink,
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

const fires = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).some(f => f.sink_type === 'prompt_injection');

describe('cognium-dev #267 — prompt-injection safety gate', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ── True positives: untrusted into instructions / system role — FIRE ───

  it('Python — untrusted concatenated into content fires', async () => {
    expect(fires(await analyze(PY(`{"role":"user","content":"Follow policy.\\n" + user}`), 'p.py', 'python'))).toBe(true);
  });

  it('Python — untrusted in a system role fires', async () => {
    expect(fires(await analyze(PY(`{"role":"system","content":user},{"role":"user","content":"hi"}`), 'p.py', 'python'))).toBe(true);
  });

  it('Python — untrusted interpolated into an instruction f-string fires', async () => {
    expect(fires(await analyze(PY(`{"role":"user","content":f"Follow policy. {user}"}`), 'p.py', 'python'))).toBe(true);
  });

  it('Python — untrusted concatenated with instructions via an intermediate var fires', async () => {
    const r = await analyze(PY(`{"role":"user","content":bad}`, `    bad = "Follow policy. " + user\n`), 'p.py', 'python');
    expect(fires(r)).toBe(true);
  });

  it('JS — untrusted concatenated into content fires', async () => {
    expect(fires(await analyze(JS(`{ role: 'user', content: 'Follow policy.\\n' + user }`), 'p.js', 'javascript'))).toBe(true);
  });

  it('JS — untrusted in an instruction template literal fires', async () => {
    expect(fires(await analyze(JS(`{ role: 'user', content: \`Follow policy. \${user}\` }`), 'p.js', 'javascript'))).toBe(true);
  });

  // ── Role separation alone is NOT a sanitizer (fires, per #248) ─────────

  it('Python — role-separated standalone user content still fires (not a sanitizer)', async () => {
    const r = await analyze(PY(`{"role":"system","content":"Follow policy."},{"role":"user","content":user}`), 'p.py', 'python');
    expect(fires(r)).toBe(true);
  });

  // ── Delimiter-wrapped safe mirror — SUPPRESSED ─────────────────────────

  it('Python — delimiter-wrapped (via var) is clean', async () => {
    const r = await analyze(PY(`{"role":"user","content":wrapped}`, `    wrapped = "<user_question>" + user + "</user_question>"\n`), 'p.py', 'python');
    expect(fires(r)).toBe(false);
  });

  it('Python — delimiter-wrapped (inline) is clean', async () => {
    const r = await analyze(PY(`{"role":"user","content":"<user_question>" + user + "</user_question>"}`), 'p.py', 'python');
    expect(fires(r)).toBe(false);
  });

  it('JS — delimiter-wrapped (via var) is clean', async () => {
    const r = await analyze(JS(`{ role: 'user', content: w }`, `  const w = '<user_question>' + user + '</user_question>';\n`), 'p.js', 'javascript');
    expect(fires(r)).toBe(false);
  });

  // ── Go: struct-field taint (recall) + builder-pattern gate (precision) ─

  const GO = (sysContent: string, userContent: string) => `package main
import (
	"net/http"
	openai "github.com/sashabaranov/go-openai"
)
func handler(r *http.Request, client *openai.Client) {
	user := r.URL.Query().Get("q")
	req := openai.ChatCompletionRequest{
		Messages: []openai.ChatCompletionMessage{
			{Role: "system", Content: ${sysContent}},
			{Role: "user", Content: ${userContent}},
		},
	}
	client.CreateChatCompletion(nil, req)
}`;

  it('Go — untrusted concatenated into a multi-line struct-builder prompt fires (recall)', async () => {
    const r = await analyze(GO(`"Follow policy. " + user`, `"hi"`), 'h.go', 'go');
    expect(fires(r)).toBe(true);
  });

  it('Go — delimiter-wrapped content in a multi-line struct builder is clean (builder-aware gate)', async () => {
    const r = await analyze(GO(`"Follow policy."`, `"<user_question>" + user + "</user_question>"`), 'h.go', 'go');
    expect(fires(r)).toBe(false);
  });

  // ── Classifier units ──────────────────────────────────────────────────

  it('classifyPromptCall: instruction concat/system → unsafe; delimiter-wrap → safe; role-sep/standalone → unknown (kept)', () => {
    const L = (s: string) => [s];
    expect(classifyPromptCall(`create(messages=[{"role":"user","content":"instr " + x}])`, L(''))).toBe('unsafe');
    expect(classifyPromptCall(`create(messages=[{"role":"system","content":x}])`, L(''))).toBe('unsafe');
    expect(classifyPromptCall(`create(messages=[{"role":"user","content":"<q>" + x + "</q>"}])`, L(''))).toBe('safe');
    expect(classifyPromptCall(`create(messages=[{"role":"user","content":x}])`, L(''))).toBe('unknown');
  });

  it('classifyPromptSink traces a Go builder var to classify the message structure', () => {
    const lines = [
      'user := r.URL.Query().Get("q")',
      'req := openai.ChatCompletionRequest{Messages: []openai.ChatCompletionMessage{',
      '{Role: "user", Content: "<user_question>" + user + "</user_question>"},',
      '}}',
      'client.CreateChatCompletion(nil, req)',
    ];
    expect(classifyPromptSink('client.CreateChatCompletion(nil, req)', lines)).toBe('safe');
  });

  it('scanValue does not truncate on } inside f-string / template interpolation', () => {
    expect(scanValue(`content:f"a {user}"}`, 'content:'.length)).toBe('f"a {user}"');
    expect(scanValue('content:`a ${user}`}', 'content:'.length)).toBe('`a ${user}`');
  });

  it('isDelimiterLiteral recognizes boundary markers but not instruction text', () => {
    expect(isDelimiterLiteral('<user_question>')).toBe(true);
    expect(isDelimiterLiteral('</user_question>')).toBe(true);
    expect(isDelimiterLiteral('[data]')).toBe(true);
    expect(isDelimiterLiteral('Follow policy.')).toBe(false);
  });
});
