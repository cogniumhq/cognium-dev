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

  it('xss_eval_safe_json: JSON.parse should sanitize (actual benchmark code)', async () => {
    // Actual benchmark code: JSON.parse + console.log (no dangerous sinks)
    const code = `
const params = new URLSearchParams(window.location.search);
const data = params.get('data');
const parsed = JSON.parse(data);
console.log(parsed);
`;
    const result = await analyze(code, 'test.js', 'javascript');
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('SANITIZERS:', JSON.stringify(result.taint.sanitizers, null, 2));
    // JSON.parse should appear as sanitizer
    expect(result.taint.sanitizers.some(s => s.method.includes('parse'))).toBe(true);
    // No XSS / code-injection sinks should remain (JSON.parse sanitizes those).
    // console.log is now modeled as a low-severity log_injection sink (issue #44);
    // that is unrelated to XSS and JSON.parse does not sanitize CRLF for log forging,
    // so it is expected to remain in the sinks list.
    const dangerous = result.taint.sinks.filter(s =>
      s.type === 'xss' || s.type === 'code_injection' || s.type === 'sql_injection' || s.type === 'command_injection'
    );
    expect(dangerous.length).toBe(0);
  });

  it('xss_location_safe_validated: validated URL redirect is safe', async () => {
    const code = `
const params = new URLSearchParams(window.location.search);
const redirect = params.get('url');
const allowedHosts = ['example.com', 'trusted.com'];
try {
  const url = new URL(redirect);
  if (allowedHosts.includes(url.hostname)) {
    window.location.href = redirect;
  }
} catch (e) {
  console.error('Invalid URL');
}
`;
    const result = await analyze(code, 'test.js', 'javascript');
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('SANITIZERS:', JSON.stringify(result.taint.sanitizers, null, 2));
    // Validated redirect should have no sinks (or be sanitized)
    expect(result.taint.sinks.length).toBe(0);
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

  it('cmdi_stdin_to_command: stdin().read_line should be a source and Command.arg a sink', async () => {
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
    expect(result.taint.sources.length).toBeGreaterThan(0);
    expect(result.taint.sinks.some(s => s.type === 'command_injection')).toBe(true);
  });

  it('cmdi_stdin_to_command: multi-line Command chain should produce cmdi sink', async () => {
    const code = `
use std::io::{self, BufRead};
use std::process::Command;

fn run_from_stdin() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let cmd = line.unwrap();
        Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .spawn()
            .expect("Failed");
    }
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    expect(result.taint.sources.length).toBeGreaterThan(0);
    expect(result.taint.sinks.some(s => s.type === 'command_injection')).toBe(true);
  });

  it('cmdi_axum_body_to_command: multi-line Json body to Command should produce cmdi sink', async () => {
    const code = `
use axum::extract::Json;
use std::process::Command;
use serde::Deserialize;

#[derive(Deserialize)]
struct CmdRequest {
    command: String,
}

async fn execute_cmd(Json(payload): Json<CmdRequest>) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(&payload.command)
        .output()
        .expect("Failed");
    String::from_utf8_lossy(&output.stdout).to_string()
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    expect(result.taint.sources.length).toBeGreaterThan(0);
    expect(result.taint.sinks.some(s => s.type === 'command_injection')).toBe(true);
  });

  it('open_redirect_safe_relative: starts_with should sanitize open_redirect', async () => {
    const code = `
use actix_web::{web, HttpRequest, HttpResponse};

async fn safe_redirect(req: HttpRequest) -> HttpResponse {
    let page = req.query_string();
    if !page.starts_with('/') || page.contains("://") {
        return HttpResponse::BadRequest().body("Invalid redirect");
    }
    HttpResponse::Found()
        .insert_header(("Location", page))
        .finish()
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('SANITIZERS:', JSON.stringify(result.taint.sanitizers, null, 2));
    // starts_with/contains should be detected as sanitizers that remove open_redirect
    const redirectSanitizers = result.taint.sanitizers.filter(
      s => s.sanitizes.includes('open_redirect')
    );
    expect(redirectSanitizers.length).toBeGreaterThan(0);
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
    // Test with ACTUAL benchmark code (receiver is warp::reply, not just reply)
    const code = `
use warp::Filter;

async fn greet_warp(name: String) -> impl warp::Reply {
    let html = format!("<html><body><h1>Hello, {}!</h1></body></html>", name);
    warp::reply::html(html)
}
`;
    const result = await analyze(code, 'test.rs', 'rust');
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    console.log('CALLS:', JSON.stringify(result.calls.map(c => ({
      method: c.method_name, receiver: c.receiver, args: c.arguments
    })), null, 2));
    expect(result.taint.sinks.some(s => s.method === 'html')).toBe(true);
  });

  // -------------------------------------------------------------------------
  // v3.18.8 additions: server-side XSS sanitizers (ServersideEscape.java)
  // -------------------------------------------------------------------------

  it('serverside_escape_url: encodeURL wrapper should sanitize XSS', async () => {
    const code = `
import java.net.URLEncoder;

public class ServersideEscape {
  private String encodeURL(String value) {
    try {
      return URLEncoder.encode(value, "UTF-8");
    } catch (Exception e) { return null; }
  }

  public void doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws java.io.IOException {
    String echoedParam = request.getParameter("q");
    response.getWriter().println(encodeURL(echoedParam));
  }
}
`;
    const result = await analyze(code, 'ServersideEscape.java', 'java');
    const encodeUrlSanitizers = result.taint.sanitizers.filter(s => s.method.includes('encodeURL'));
    expect(encodeUrlSanitizers.length).toBeGreaterThan(0);
  });

  it('serverside_escape_html: htmlEscape wrapper should sanitize XSS', async () => {
    const code = `
public class ServersideEscape {
  private String htmlEscape(String value) {
    return value.replace("<", "&lt;").replace("&", "&amp;").replace(">", "&gt;");
  }

  public void doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws java.io.IOException {
    String echoedParam = request.getParameter("q");
    response.getWriter().println(htmlEscape(echoedParam));
  }
}
`;
    const result = await analyze(code, 'ServersideEscape.java', 'java');
    const htmlEscapeSanitizers = result.taint.sanitizers.filter(s => s.method.includes('htmlEscape'));
    expect(htmlEscapeSanitizers.length).toBeGreaterThan(0);
  });

  it('owasp_encoder: Encode.forHtml should sanitize XSS', async () => {
    const code = `
import org.owasp.encoder.Encode;

public class Safe {
  public void doGet(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws java.io.IOException {
    String userInput = request.getParameter("q");
    response.getWriter().println(Encode.forHtml(userInput));
  }
}
`;
    const result = await analyze(code, 'Safe.java', 'java');
    const encodeSanitizers = result.taint.sanitizers.filter(s => s.method.includes('forHtml'));
    expect(encodeSanitizers.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // v3.18.8 additions: DOM propagation (DOMPropagation benchmark)
  // -------------------------------------------------------------------------

  it('dom_propagation_window_status: window.status should be a taint conduit', async () => {
    const code = `
var payload = location.hash.substr(1);
window.status = payload;
var retrieved_payload = window.status;
eval(retrieved_payload);
`;
    const result = await analyze(code, 'dompropagation.js', 'javascript');
    console.log('SOURCES:', JSON.stringify(result.taint.sources, null, 2));
    console.log('SINKS:', JSON.stringify(result.taint.sinks, null, 2));
    // At least one source should be from window.status or location.hash
    expect(result.taint.sources.length).toBeGreaterThan(0);
    // There should be an eval sink
    expect(result.taint.sinks.some(s => s.method === 'eval')).toBe(true);
  });

  it('dom_propagation_document_title: document.title should be a taint conduit', async () => {
    const code = `
document.title = location.hash;
var t = document.title;
document.body.innerHTML = t;
`;
    const result = await analyze(code, 'title.js', 'javascript');
    expect(result.taint.sources.some(s =>
      s.location?.includes('document.title') || s.location?.includes('location.hash')
    )).toBe(true);
  });

  it('dom_propagation_localstorage: localStorage.getItem should be a source', async () => {
    const code = `
var data = localStorage.getItem('key');
document.body.innerHTML = data;
`;
    const result = await analyze(code, 'ls.js', 'javascript');
    expect(result.taint.sources.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // v3.18.8 additions: new CWE-094 sinks
  // -------------------------------------------------------------------------

  it('cwe094_jexl: JexlEngine.createExpression should be a sink', async () => {
    const code = `
import org.apache.commons.jexl3.JexlEngine;

public class Vuln {
  public void handle(javax.servlet.http.HttpServletRequest request, JexlEngine engine) {
    String expr = request.getParameter("expr");
    engine.createExpression(expr);
  }
}
`;
    const result = await analyze(code, 'Vuln.java', 'java');
    expect(result.taint.sinks.some(s => s.method === 'createExpression' && s.type === 'code_injection')).toBe(true);
  });

  it('cwe094_janino: Janino ExpressionEvaluator.cook should be a sink', async () => {
    const code = `
import org.codehaus.janino.ExpressionEvaluator;

public class Vuln {
  public void handle(javax.servlet.http.HttpServletRequest request, ExpressionEvaluator ev) throws Exception {
    String expr = request.getParameter("expr");
    ev.cook(expr);
  }
}
`;
    const result = await analyze(code, 'Vuln.java', 'java');
    expect(result.taint.sinks.some(s => s.method === 'cook' && s.type === 'code_injection')).toBe(true);
  });

  it('cwe094_thymeleaf: StandardExpressionParser.parseExpression should be a sink', async () => {
    const code = `
import org.thymeleaf.standard.expression.StandardExpressionParser;
import org.thymeleaf.context.IExpressionContext;

public class Vuln {
  public void handle(javax.servlet.http.HttpServletRequest request, StandardExpressionParser parser, IExpressionContext ctx) {
    String expr = request.getParameter("expr");
    parser.parseExpression(ctx, expr);
  }
}
`;
    const result = await analyze(code, 'Vuln.java', 'java');
    expect(result.taint.sinks.some(s => s.method === 'parseExpression' && s.type === 'code_injection')).toBe(true);
  });

  it('cwe094_camel_simple: SimpleLanguage.createExpression should be a sink', async () => {
    const code = `
import org.apache.camel.language.simple.SimpleLanguage;

public class Vuln {
  public void handle(javax.servlet.http.HttpServletRequest request, SimpleLanguage lang) {
    String expr = request.getParameter("expr");
    lang.createExpression(expr);
  }
}
`;
    const result = await analyze(code, 'Vuln.java', 'java');
    expect(result.taint.sinks.some(s => s.method === 'createExpression' && s.type === 'code_injection')).toBe(true);
  });
});
