/**
 * cognium-dev #248 — Prompt injection sink category (CWE-1427).
 *
 * Tainted input flowing into a generative-model prompt-construction API
 * (chat/completions/messages) is a prompt-injection risk. This test suite
 * pins the v1 sink coverage across Python, JS/TS, Java, Go for the major
 * client libraries.
 *
 * v1 scope: broad positional match (arg_positions [0..3]) covers both
 * ordered-positional and kwarg-flattened call shapes. Argname-precise
 * filtering is a documented follow-up.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasPromptInjectionFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === 'prompt_injection');

const countPromptInjection = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'prompt_injection').length;

const hasPromptInjectionSignal = (r: any) =>
  hasPromptInjectionFlow(r) || countPromptInjection(r) > 0;

describe('#248 — prompt injection sink category (CWE-1427)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ------------------------------------------------------------------
  // Must-fire — Python
  // ------------------------------------------------------------------

  it('TP — Python Flask + openai.chat.completions.create fires', async () => {
    const code = [
      'import openai',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '@app.route("/chat")',
      'def handle():',
      '    user_msg = request.args.get("q")',
      '    prompt = f"Ignore previous instructions. {user_msg}"',
      '    return openai.chat.completions.create(',
      '        model="gpt-4o",',
      '        messages=[{"role": "user", "content": prompt}],',
      '    )',
    ].join('\n');
    const r = await analyze(code, 'chat.py', 'python');
    expect(hasPromptInjectionSignal(r)).toBe(true);
  });

  it('TP — Python Flask + anthropic messages.create fires', async () => {
    const code = [
      'import anthropic',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      'client = anthropic.Anthropic()',
      '',
      '@app.route("/ask")',
      'def ask():',
      '    user_msg = request.args.get("q")',
      '    return client.messages.create(',
      '        model="claude-3-5-sonnet-20241022",',
      '        max_tokens=1024,',
      '        messages=[{"role": "user", "content": user_msg}],',
      '    )',
    ].join('\n');
    const r = await analyze(code, 'ask.py', 'python');
    expect(hasPromptInjectionSignal(r)).toBe(true);
  });

  it('TP — Python Flask + litellm.completion fires', async () => {
    const code = [
      'import litellm',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '@app.route("/ll")',
      'def ll():',
      '    user_msg = request.args.get("q")',
      '    return litellm.completion(',
      '        model="gpt-4o",',
      '        messages=[{"role": "user", "content": user_msg}],',
      '    )',
    ].join('\n');
    const r = await analyze(code, 'll.py', 'python');
    expect(hasPromptInjectionSignal(r)).toBe(true);
  });

  // ------------------------------------------------------------------
  // Must-fire — JS/TS
  // ------------------------------------------------------------------

  it('TP — Express + openai chat.completions.create fires', async () => {
    const code = [
      "import express from 'express';",
      "import OpenAI from 'openai';",
      '',
      'const app = express();',
      'const client = new OpenAI();',
      '',
      "app.post('/chat', async (req, res) => {",
      '  const userMsg = req.body.q;',
      '  const completion = await client.chat.completions.create({',
      "    model: 'gpt-4o',",
      "    messages: [{ role: 'user', content: userMsg }],",
      '  });',
      '  res.json(completion);',
      '});',
    ].join('\n');
    const r = await analyze(code, 'chat.ts', 'typescript');
    expect(hasPromptInjectionSignal(r)).toBe(true);
  });

  it('TP — Express + Vercel AI SDK generateText fires', async () => {
    const code = [
      "import express from 'express';",
      "import { generateText } from 'ai';",
      "import { openai } from '@ai-sdk/openai';",
      '',
      'const app = express();',
      '',
      "app.post('/summary', async (req, res) => {",
      '  const userInput = req.body.text;',
      '  const { text } = await generateText({',
      "    model: openai('gpt-4o'),",
      '    prompt: userInput,',
      '  });',
      '  res.json({ text });',
      '});',
    ].join('\n');
    const r = await analyze(code, 'summary.ts', 'typescript');
    expect(hasPromptInjectionSignal(r)).toBe(true);
  });

  // ------------------------------------------------------------------
  // Must-fire — Java
  // ------------------------------------------------------------------

  it('TP — Java Spring + LangChain4j ChatLanguageModel.generate fires', async () => {
    const code = [
      'package com.example;',
      'import dev.langchain4j.model.chat.ChatLanguageModel;',
      'import org.springframework.web.bind.annotation.*;',
      '',
      '@RestController',
      'public class ChatCtrl {',
      '  private final ChatLanguageModel model;',
      '  public ChatCtrl(ChatLanguageModel model) { this.model = model; }',
      '  @GetMapping("/ask")',
      '  public String ask(@RequestParam String q) {',
      '    return model.generate(q);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'ChatCtrl.java', 'java');
    expect(hasPromptInjectionSignal(r)).toBe(true);
  });

  // ------------------------------------------------------------------
  // Must-fire — Go
  // ------------------------------------------------------------------

  it('TP — Go net/http + go-openai CreateChatCompletion fires', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "context"',
      '  "net/http"',
      '  openai "github.com/sashabaranov/go-openai"',
      ')',
      '',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '  q := r.URL.Query().Get("q")',
      '  client := openai.NewClient("sk-x")',
      '  client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{',
      '    Model: openai.GPT4o,',
      '    Messages: []openai.ChatCompletionMessage{{Role: "user", Content: q}},',
      '  })',
      '}',
    ].join('\n');
    const r = await analyze(code, 'main.go', 'go');
    expect(hasPromptInjectionSignal(r)).toBe(true);
  });

  // ------------------------------------------------------------------
  // Must-not-fire — clean, templated-only content
  // ------------------------------------------------------------------

  it('FP-guard — Python: hardcoded messages, no source → no finding', async () => {
    const code = [
      'import openai',
      '',
      'def hello_bot():',
      '    return openai.chat.completions.create(',
      '        model="gpt-4o",',
      '        messages=[{"role": "user", "content": "Hello, world"}],',
      '    )',
    ].join('\n');
    const r = await analyze(code, 'clean.py', 'python');
    expect(countPromptInjection(r)).toBe(0);
  });

  it('FP-guard — TS: hardcoded messages, no source → no finding', async () => {
    const code = [
      "import OpenAI from 'openai';",
      '',
      'const client = new OpenAI();',
      '',
      'export async function hello() {',
      '  return client.chat.completions.create({',
      "    model: 'gpt-4o',",
      "    messages: [{ role: 'user', content: 'Hello, world' }],",
      '  });',
      '}',
    ].join('\n');
    const r = await analyze(code, 'clean.ts', 'typescript');
    expect(countPromptInjection(r)).toBe(0);
  });
});
