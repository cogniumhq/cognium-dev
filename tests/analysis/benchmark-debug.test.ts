/**
 * Debug test: run analyze() on each failing benchmark snippet
 * to see exactly what sources/sinks/findings are produced.
 */
import { describe, it, expect } from 'vitest';
import { analyze } from '../../src/analyzer.js';

describe('Benchmark gap debugging', () => {
  // -------------------------------------------------------------------------
  // JS/HTML
  // -------------------------------------------------------------------------

  it('xss_docwrite_referrer: document.referrer should be a source', async () => {
    const code = `
const ref = document.referrer;
document.write(ref);
`;
    const result = await analyze(code, 'test.js', 'javascript');
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('FINDINGS:', result.findings?.map(f => `${f.rule_id}: ${f.message} (line ${f.line})`));
    expect(result.taint.sources.length).toBeGreaterThan(0);
  });

  it('xss_event_onclick: setAttribute("onclick", x) should be a sink', async () => {
    const code = `
function handleInput(userInput) {
  const el = document.getElementById('target');
  el.setAttribute('onclick', userInput);
}
`;
    const result = await analyze(code, 'test.js', 'javascript');
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('FINDINGS:', result.findings?.map(f => `${f.rule_id}: ${f.message} (line ${f.line})`));
    expect(result.taint.sinks.some(s => s.method === 'setAttribute')).toBe(true);
  });

  it('xss_css_style_attribute: el.style.cssText = x should be a sink', async () => {
    const code = `
function injectCSS(userInput) {
  const el = document.getElementById('target');
  el.style.cssText = userInput;
}
`;
    const result = await analyze(code, 'test.js', 'javascript');
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('FINDINGS:', result.findings?.map(f => `${f.rule_id}: ${f.message} (line ${f.line})`));
    expect(result.taint.sinks.length).toBeGreaterThan(0);
  });

  it('xss_eval_safe_json: JSON.parse should sanitize', async () => {
    const code = `
const data = location.hash;
const parsed = JSON.parse(data);
document.write(parsed);
`;
    const result = await analyze(code, 'test.js', 'javascript');
    console.log('CALLS:', JSON.stringify(result.calls.map(c => ({
      method: c.method_name, receiver: c.receiver, class: c.class_name
    })), null, 2));
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('SANITIZERS:', JSON.stringify(result.taint.sanitizers, null, 2));
    console.log('FINDINGS:', result.findings?.map(f => `${f.rule_id}: ${f.message} (line ${f.line})`));
    // JSON.parse should appear as sanitizer (method is formatted as "JSON.parse()")
    expect(result.taint.sanitizers.some(s => s.method.includes('parse'))).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Bash
  // -------------------------------------------------------------------------

  it('ssrf_safe_hardcoded_curl: literal URL should not be SSRF', async () => {
    const code = `#!/bin/bash
curl -s "https://api.example.com/data"
`;
    const result = await analyze(code, 'test.sh', 'bash');
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('CALLS:', JSON.stringify(result.calls.map(c => ({
      method: c.method_name,
      args: c.arguments.map(a => ({ pos: a.position, literal: a.literal, expr: a.expression, variable: a.variable }))
    })), null, 2));
    console.log('FINDINGS:', result.findings?.map(f => `${f.rule_id}: ${f.message} (line ${f.line})`));
    // Should have 0 sinks after filtering (literal args)
    expect(result.taint.sinks.length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Rust
  // -------------------------------------------------------------------------

  it('cmdi_stdin_to_command: stdin().read_line should be a source', async () => {
    const code = `
use std::io;
use std::process::Command;

fn main() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    Command::new("sh").arg("-c").arg(&input).output().unwrap();
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('CALLS:', JSON.stringify(result.calls.map(c => ({
      method: c.method_name, receiver: c.receiver, class: c.class_name
    })), null, 2));
    expect(result.taint.sources.length).toBeGreaterThan(0);
  });

  it('open_redirect_see_other: Redirect::see_other should be a sink', async () => {
    const code = `
use axum::response::Redirect;

async fn handler(url: String) -> Redirect {
    Redirect::see_other(&url)
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('CALLS:', JSON.stringify(result.calls.map(c => ({
      method: c.method_name, receiver: c.receiver, class: c.class_name
    })), null, 2));
    expect(result.taint.sinks.length).toBeGreaterThan(0);
  });

  it('open_redirect_header: Response::builder().header should be a sink', async () => {
    const code = `
use http::Response;

fn redirect(url: &str) -> Response<()> {
    Response::builder()
        .header("Location", url)
        .body(())
        .unwrap()
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('CALLS:', JSON.stringify(result.calls.map(c => ({
      method: c.method_name, receiver: c.receiver, class: c.class_name
    })), null, 2));
    expect(result.taint.sinks.some(s => s.method === 'header')).toBe(true);
  });

  it('xss_warp_html_reply: warp::reply::html should be a sink', async () => {
    const code = `
use warp::reply;

fn render(input: &str) -> impl warp::Reply {
    reply::html(format!("<h1>{}</h1>", input))
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('CALLS:', JSON.stringify(result.calls.map(c => ({
      method: c.method_name, receiver: c.receiver, class: c.class_name
    })), null, 2));
    expect(result.taint.sinks.some(s => s.method === 'html')).toBe(true);
  });
});
