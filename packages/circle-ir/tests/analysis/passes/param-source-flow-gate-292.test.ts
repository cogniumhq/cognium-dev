/**
 * cognium-dev #292 — flows whose only source is a bare function parameter
 * (`interprocedural_param`) are off the default path; the
 * `speculativeParamSources` opt-in restores them.
 *
 * Fixtures are the seven safe aisec mirrors from the issue (JS + TS), the two
 * Rust fixtures from the follow-up comment, plus request-sourced true
 * positives that must keep firing with the flag unset.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import type { SupportedLanguage } from '../../../src/types/index.js';

type Fixture = { file: string; lang: SupportedLanguage; code: string; sink: string };

// ---------------------------------------------------------------------------
// Safe fixtures (#292) — expected clean by default.
// ---------------------------------------------------------------------------

const SAFE: Fixture[] = [
  {
    file: 'benign_bounded_call.js', lang: 'javascript', sink: 'prompt_injection',
    code: `const OpenAI = require('openai');
const client = new OpenAI();
function answer(q) {
  return client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: q }],
    max_tokens: 256,
  });
}
module.exports = { answer };
`,
  },
  {
    file: 'safe_llm05_output_to_exec.js', lang: 'javascript', sink: 'prompt_injection',
    code: `const OpenAI = require('openai');
const { execFile } = require('child_process');
const client = new OpenAI();
async function suggest(q) {
  const r = await client.chat.completions.create({ model: 'gpt-4', messages: [{ role: 'user', content: q }] });
  const choice = r.choices[0].message.content.trim();
  const ALLOWED = { list: ['ls'], date: ['date'] };
  if (!ALLOWED[choice]) throw new Error('not allowed');
  execFile(ALLOWED[choice][0], []);
}
module.exports = { suggest };
`,
  },
  {
    file: 'safe_llm05_output_to_sql.js', lang: 'javascript', sink: 'prompt_injection',
    code: `const OpenAI = require('openai');
const client = new OpenAI();
const db = require('./db');
async function lookup(q) {
  const r = await client.chat.completions.create({ model: 'gpt-4',
    messages: [{ role: 'user', content: q }] });
  const name = r.choices[0].message.content;
  return db.query('SELECT * FROM items WHERE name = $1', [name]);
}
module.exports = { lookup };
`,
  },
  {
    file: 'safe_llm10_no_token_cap.js', lang: 'javascript', sink: 'prompt_injection',
    code: `const OpenAI = require('openai');
const client = new OpenAI();
const MAX_INPUT = 8000;
function summarize(userText) {
  if (userText.length > MAX_INPUT) throw new Error('input too large');
  return client.chat.completions.create({ model: 'gpt-4',
    messages: [{ role: 'user', content: userText }], max_tokens: 512 });
}
module.exports = { summarize };
`,
  },
  {
    file: 'safe_llm10_unbounded_agent_loop.js', lang: 'javascript', sink: 'prompt_injection',
    code: `const OpenAI = require('openai');
const client = new OpenAI();
const MAX_STEPS = 8;
async function runAgent(task) {
  let history = [{ role: 'user', content: task }];
  for (let i = 0; i < MAX_STEPS; i++) {
    const r = await client.chat.completions.create({ model: 'gpt-4',
      messages: [{ role: 'user', content: task }], max_tokens: 256 });
    history.push(r.choices[0].message);
    if (r.choices[0].finish_reason === 'stop') break;
  }
  return history;
}
module.exports = { runAgent };
`,
  },
  // TS mirrors with untyped parameters (the shape that seeds a bare-param
  // source in TypeScript; \`q: string\` is not a seeded type).
  {
    file: 'benign_bounded_call.ts', lang: 'typescript', sink: 'prompt_injection',
    code: `import OpenAI from 'openai';
const client = new OpenAI();
export function answer(q) {
  return client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: q }],
    max_tokens: 256,
  });
}
`,
  },
  {
    file: 'safe_llm10_no_token_cap.ts', lang: 'typescript', sink: 'prompt_injection',
    code: `import OpenAI from 'openai';
const client = new OpenAI();
const MAX_INPUT = 8000;
export function summarize(userText) {
  if (userText.length > MAX_INPUT) throw new Error('input too large');
  return client.chat.completions.create({ model: 'gpt-4',
    messages: [{ role: 'user', content: userText }], max_tokens: 512 });
}
`,
  },
  {
    file: 'safe_prompt_inject_indirect.rs', lang: 'rust', sink: 'ssrf',
    code: `pub fn summarize_url(url: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let page = reqwest::blocking::get(url)?.text()?;
    Ok((page.clone(), page))
}
`,
  },
  {
    file: 'safe_perf_streamed.rs', lang: 'rust', sink: 'path_traversal',
    code: `use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn process_log(path: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let f = File::open(path).unwrap();
    for line in BufReader::new(f).lines().take(max) { out.push(line.unwrap()); }
    out
}
`,
  },
];

// ---------------------------------------------------------------------------
// True positives — must keep firing with the flag unset.
// ---------------------------------------------------------------------------

const TP: Fixture[] = [
  {
    file: 'tp_prompt_req.js', lang: 'javascript', sink: 'prompt_injection',
    code: `const express = require('express');
const OpenAI = require('openai');
const app = express();
const client = new OpenAI();
app.get('/ask', async (req, res) => {
  const q = req.query.q;
  const r = await client.chat.completions.create({ model: 'gpt-4',
    messages: [{ role: 'system', content: 'You are helpful. ' + q }] });
  res.send(r.choices[0].message.content);
});
`,
  },
  {
    file: 'tp_ssrf_req.ts', lang: 'typescript', sink: 'ssrf',
    code: `import express from 'express';
const app = express();
app.get('/fetch', async (req, res) => {
  const target = req.query.url as string;
  const r = await fetch(target);
  res.send(await r.text());
});
`,
  },
  {
    file: 'tp_sqli_req.js', lang: 'javascript', sink: 'sql_injection',
    code: `const express = require('express');
const db = require('./db');
const app = express();
app.get('/u', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
});
`,
  },
  // Framework-handler parameters are request input, not bare parameters.
  {
    file: 'rocket_route.rs', lang: 'rust', sink: 'command_injection',
    code: `use rocket::get;
use std::process::Command;

#[get("/exec/<cmd>")]
fn execute(cmd: String) -> String {
    let output = Command::new(&cmd).output().expect("failed");
    String::from_utf8_lossy(&output.stdout).to_string()
}
`,
  },
  {
    file: 'actix_handler.rs', lang: 'rust', sink: 'deserialization',
    code: `use actix_web::{web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct UserData { name: String }

async fn parse_user_json(body: String) -> HttpResponse {
    let user: UserData = serde_json::from_str(&body).unwrap();
    HttpResponse::Ok().json(user.name)
}
`,
  },
  {
    file: 'flask_route.py', lang: 'python', sink: 'command_injection',
    code: `import os
from flask import Flask
app = Flask(__name__)

@app.route('/run/<cmd>')
def run(cmd):
    os.system(cmd)
    return "ok"
`,
  },
];

const fires = (r: Awaited<ReturnType<typeof analyze>>, sink: string) =>
  (r.taint.flows ?? []).some(f => f.sink_type === sink);

describe('cognium-dev #292 — bare-parameter flows are opt-in', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  for (const fx of SAFE) {
    it(`default: ${fx.file} is silent`, async () => {
      const r = await analyze(fx.code, fx.file, fx.lang);
      expect((r.taint.flows ?? []).filter(f => f.source_type === 'interprocedural_param')).toEqual([]);
      expect(fires(r, fx.sink)).toBe(false);
    });

    it(`opt-in: ${fx.file} reports ${fx.sink}`, async () => {
      const r = await analyze(fx.code, fx.file, fx.lang, { speculativeParamSources: true });
      expect(fires(r, fx.sink)).toBe(true);
    });
  }

  it('default: the bare-parameter source itself is kept (only the flow is gated)', async () => {
    const r = await analyze(SAFE[0].code, SAFE[0].file, SAFE[0].lang);
    expect(r.taint.sources.some(s => s.type === 'interprocedural_param')).toBe(true);
  });

  for (const fx of TP) {
    it(`default: true positive ${fx.file} still reports ${fx.sink}`, async () => {
      const r = await analyze(fx.code, fx.file, fx.lang);
      expect(fires(r, fx.sink)).toBe(true);
    });
  }

  it('Java is exempt — interprocedural_param flows are left to the entry-point gate', async () => {
    const code = `import java.sql.*;
public class Repo {
  public void find(Connection c, String name) throws SQLException {
    c.createStatement().executeQuery("SELECT * FROM t WHERE n = '" + name + "'");
  }
}`;
    const withFlag = await analyze(code, 'Repo.java', 'java', { speculativeParamSources: true });
    const r = await analyze(code, 'Repo.java', 'java');
    expect(r.taint.flows.length).toBe(withFlag.taint.flows.length);
  });

  it('disabledPasses: param-source-flow-gate restores the pre-#292 flow list', async () => {
    const r = await analyze(SAFE[0].code, SAFE[0].file, SAFE[0].lang, { disabledPasses: ['param-source-flow-gate'] });
    expect(fires(r, 'prompt_injection')).toBe(true);
  });
});
