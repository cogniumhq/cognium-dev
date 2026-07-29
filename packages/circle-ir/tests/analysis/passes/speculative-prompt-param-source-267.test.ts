/**
 * Tests for cognium-dev #267 — speculative param-source (opt-in, off-default).
 *
 * When `AnalyzerOptions.speculativeParamSources` is set, function parameters
 * inside functions that contain a `prompt_injection` sink are seeded as
 * untrusted sources — for library/agent/SDK code whose untrusted entry is a
 * bare parameter, with no in-file request source to seed taint.
 *
 * CRITICAL: the flag defaults OFF. The precision benchmarks never set it, so
 * the 0%-FPR moat is untouched — the first test locks that default.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import { looksLikeTextParam } from '../../../src/analysis/passes/speculative-prompt-param-source-pass.js';

const GO_PARAM = (content: string) => `package main
import (
	"context"
	openai "github.com/sashabaranov/go-openai"
)
func BuildAndSend(user string, client *openai.Client) {
	req := openai.ChatCompletionRequest{Messages: []openai.ChatCompletionMessage{
		{Role: "system", Content: ${content}},
	}}
	client.CreateChatCompletion(context.Background(), req)
}`;

const PY_PARAM = (content: string) => `from openai import OpenAI
def ask(user, client: OpenAI):
    client.chat.completions.create(model="m", messages=[{"role":"user","content":${content}}])`;

const fires = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).some(f => f.sink_type === 'prompt_injection');

describe('cognium-dev #267 — speculative param-source (off by default)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('DEFAULT (flag unset) — a bare param does NOT seed a source or fire (moat)', async () => {
    const r = await analyze(GO_PARAM(`"Follow policy. " + user`), 'h.go', 'go');
    expect(r.taint.sources.length).toBe(0);
    expect(fires(r)).toBe(false);
  });

  it('flag explicitly false — unchanged from default', async () => {
    const r = await analyze(GO_PARAM(`"Follow policy. " + user`), 'h.go', 'go', { speculativeParamSources: false });
    expect(fires(r)).toBe(false);
  });

  it('Go — flag on: param → prompt sink fires; only the text param is seeded', async () => {
    const r = await analyze(GO_PARAM(`"Follow policy. " + user`), 'h.go', 'go', { speculativeParamSources: true });
    expect(fires(r)).toBe(true);
    // The *openai.Client handle param must not be seeded.
    expect(r.taint.sources.some(s => s.variable === 'client')).toBe(false);
    expect(r.taint.sources.some(s => s.variable === 'user')).toBe(true);
  });

  it('Python — flag on: untyped param → prompt sink fires', async () => {
    const r = await analyze(PY_PARAM(`"Follow policy. " + user`), 'h.py', 'python', { speculativeParamSources: true });
    expect(fires(r)).toBe(true);
  });

  it('flag on + delimiter-wrapped content — safe mirror stays clean (gate still applies)', async () => {
    const r = await analyze(PY_PARAM(`"<user_question>" + user + "</user_question>"`), 'h.py', 'python', { speculativeParamSources: true });
    expect(fires(r)).toBe(false);
  });

  it('flag on — params of a function WITHOUT a prompt sink are not seeded', async () => {
    const code = `package main
func Helper(user string) string {
	return "prefix " + user
}`;
    const r = await analyze(code, 'h.go', 'go', { speculativeParamSources: true });
    // No prompt_injection sink in this function → no speculative seeding.
    expect(r.taint.sources.some(s => s.variable === 'user')).toBe(false);
  });

  it('looksLikeTextParam keeps text/untyped params, skips handle/dependency params', () => {
    expect(looksLikeTextParam('string')).toBe(true);
    expect(looksLikeTextParam(null)).toBe(true);       // untyped (Python/JS)
    expect(looksLikeTextParam('[]byte')).toBe(true);
    expect(looksLikeTextParam('*openai.Client')).toBe(false);
    expect(looksLikeTextParam('context.Context')).toBe(false);
    expect(looksLikeTextParam('*sql.DB')).toBe(false);
    expect(looksLikeTextParam('http.ResponseWriter')).toBe(false);
  });
});
