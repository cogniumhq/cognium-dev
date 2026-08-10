/**
 * cognium-ai#281 — `generateFindings` (the scan path) dropped `prompt_injection`
 * (CWE-1427 / OWASP LLM01) flows.
 *
 * `prompt_injection` was absent from the `canSourceReachSink` reach map, so the
 * scan path emitted 0 findings even though `taint.sinks`/`taint.flows` (and the
 * downstream trust pass) already reported a valid unsanitized `http_* → LLM
 * prompt` flow — the same "two paths disagree" shape as #129. LLM01 was
 * structurally invisible to `scan` (and every corpus sweep that runs `scan`).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings, canSourceReachSink } from '../../src/analysis/findings.js';

describe('cognium-ai#281 — prompt_injection reaches the finding (scan) layer', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const scanFindings = async (code: string, file: string, lang: string) => {
    const r = await analyze(code, file, lang);
    return generateFindings(r.taint.sources, r.taint.sinks, r.dfg, file, code, lang, r.taint.sanitizers);
  };

  it('attacker-controlled sources reach prompt_injection in the reach map', () => {
    expect(canSourceReachSink('http_param', 'prompt_injection')).toBe(true);
    expect(canSourceReachSink('http_query', 'prompt_injection')).toBe(true);
    expect(canSourceReachSink('http_body', 'prompt_injection')).toBe(true);
    expect(canSourceReachSink('io_input', 'prompt_injection')).toBe(true);
    expect(canSourceReachSink('interprocedural_param', 'prompt_injection')).toBe(true);
  });

  it('Go http input → CreateChatCompletion emits a prompt_injection finding from scan (the repro)', async () => {
    const go = `package main
import ("net/http"; "github.com/sashabaranov/go-openai")
func handler(w http.ResponseWriter, r *http.Request) {
  q := r.URL.Query().Get("q")
  client := openai.NewClient("k")
  req := openai.ChatCompletionRequest{ Messages: []openai.ChatCompletionMessage{{Role: "user", Content: q}} }
  client.CreateChatCompletion(r.Context(), req)
}`;
    const findings = await scanFindings(go, 'tp.go', 'go');
    expect(findings.some(f => f.type === 'prompt_injection')).toBe(true);
  });
});
