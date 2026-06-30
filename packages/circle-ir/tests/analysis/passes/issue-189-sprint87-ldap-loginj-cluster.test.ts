/**
 * Sprint 87 — #189 variant-regression: ldap (4) + log_injection (4) cluster.
 *
 * Baseline against 3.136.0 corpus showed 5 of 8 FN:
 *   - js__ldap_v01_ldapjs.js    — ldapjs client.search filter
 *   - ts__ldap_v01_ldapts.ts    — ldapts Client.search filter (shorthand)
 *   - go__ldap_v01_goldap.go    — go-ldap NewSearchRequest slot 7
 *   - rust__ldap_v01_ldap3.rs   — ldap3 LdapConn::search slot 3
 *   - rust__loginj_v01_logcrate.rs — log::info!/warn! macros
 *
 * Four new pattern detectors close the FN cells:
 *
 *   findJsLdapInjectionFindings —
 *     ldapjs / ldapts `client.search(base, { filter: <tainted>, ... })`
 *     and the ES6 shorthand `{ filter, ... }` form. rule_id=ldap_injection,
 *     CWE-90, critical.
 *
 *   findGoLdapInjectionFindings —
 *     go-ldap `ldap.NewSearchRequest(base, scope, deref, sizeLimit,
 *     timeLimit, typesOnly, <tainted-filter>, ...)` (slot 7).
 *     String-literal-aware multiline argument walker.
 *     rule_id=ldap_injection, CWE-90, critical.
 *
 *   findRustLdapInjectionFindings —
 *     ldap3 `LdapConn::search(base, scope, &<tainted-filter>, attrs)`
 *     (slot 3) inside actix-web extractor handlers.
 *     rule_id=ldap_injection, CWE-90, critical.
 *
 *   findRustLogInjectionFindings —
 *     Rust `log::info!/warn!/error!/debug!/trace!` macros with tainted
 *     interpolation arguments. rule_id=log_injection, CWE-117, medium.
 *
 * The other 3 cells (py/js/ts log_injection) were already TP via the
 * existing configured logging sinks — verified here by a sanity TP per
 * language to lock in the coverage.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countRule = (r: any, ruleId: string) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === ruleId).length;

const hasFlowOfType = (r: any, sinkType: string) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === sinkType);

const hasLdapSignal = (r: any) =>
  hasFlowOfType(r, 'ldap_injection') ||
  hasFlowOfType(r, 'ldap') ||
  countRule(r, 'ldap_injection') > 0 ||
  countRule(r, 'ldap') > 0;

const hasLogInjSignal = (r: any) =>
  hasFlowOfType(r, 'log_injection') || countRule(r, 'log_injection') > 0;

describe('#189 Sprint 87 — ldap + log_injection cluster', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // A. JS/TS LDAP injection — ldapjs/ldapts client.search filter.

  it('A-TP: JS ldapjs client.search with `filter: <tainted>` fires', async () => {
    const code = [
      "const express = require('express');",
      "const ldap = require('ldapjs');",
      'const app = express();',
      "const client = ldap.createClient({ url: 'ldap://x' });",
      "app.get('/find', (req, res) => {",
      '  const uid = req.query.uid;',
      "  client.search('ou=u,dc=ex,dc=com', { filter: '(uid=' + uid + ')' }, () => {});",
      "  res.send('ok');",
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasLdapSignal(r)).toBe(true);
  });

  it('A-TP-shorthand: TS ldapts client.search with `{ filter }` shorthand fires', async () => {
    const code = [
      "import express from 'express';",
      "import { Client } from 'ldapts';",
      'const app = express();',
      "const client = new Client({ url: 'ldap://x' });",
      "app.get('/find', async (req, res) => {",
      '  const uid = req.query.uid as string;',
      '  const filter = `(uid=${uid})`;',
      "  const { searchEntries } = await client.search('ou=u,dc=ex,dc=com', {",
      '    filter,',
      "    scope: 'sub',",
      '  });',
      '  res.json(searchEntries);',
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.ts', 'typescript');
    expect(hasLdapSignal(r)).toBe(true);
  });

  it('A-TN: JS ldapjs with literal filter does NOT fire', async () => {
    const code = [
      "const express = require('express');",
      "const ldap = require('ldapjs');",
      'const app = express();',
      "const client = ldap.createClient({ url: 'ldap://x' });",
      "app.get('/find', (req, res) => {",
      "  client.search('ou=u', { filter: '(objectclass=*)' }, () => {});",
      "  res.send('ok');",
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasLdapSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // B. Go LDAP injection — go-ldap NewSearchRequest filter slot 7.

  it('B-TP: Go go-ldap NewSearchRequest with tainted filter fires', async () => {
    const code = [
      'package main',
      'import (',
      '  "fmt"',
      '  "net/http"',
      '  "github.com/go-ldap/ldap/v3"',
      ')',
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  uid := r.URL.Query().Get("uid")',
      '  conn, _ := ldap.DialURL("ldap://x")',
      '  defer conn.Close()',
      '  filter := fmt.Sprintf("(uid=%s)", uid)',
      '  req := ldap.NewSearchRequest(',
      '    "ou=u,dc=ex,dc=com",',
      '    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,',
      '    filter, []string{"cn"}, nil,',
      '  )',
      '  conn.Search(req)',
      '  fmt.Fprintln(w, "ok")',
      '}',
      'func main() { http.HandleFunc("/find", h); http.ListenAndServe(":8080", nil) }',
    ].join('\n');
    const r = await analyze(code, '/x/a.go', 'go');
    expect(hasLdapSignal(r)).toBe(true);
  });

  it('B-TN: Go NewSearchRequest with literal filter does NOT fire', async () => {
    const code = [
      'package main',
      'import (',
      '  "fmt"',
      '  "net/http"',
      '  "github.com/go-ldap/ldap/v3"',
      ')',
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  conn, _ := ldap.DialURL("ldap://x")',
      '  defer conn.Close()',
      '  req := ldap.NewSearchRequest(',
      '    "ou=u,dc=ex,dc=com",',
      '    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,',
      '    "(objectclass=*)", []string{"cn"}, nil,',
      '  )',
      '  conn.Search(req)',
      '  fmt.Fprintln(w, "ok")',
      '}',
      'func main() { http.HandleFunc("/find", h); http.ListenAndServe(":8080", nil) }',
    ].join('\n');
    const r = await analyze(code, '/x/a.go', 'go');
    expect(hasLdapSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // C. Rust LDAP injection — ldap3 LdapConn::search filter slot 3.

  it('C-TP: Rust ldap3 LdapConn::search with tainted filter fires', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      'use ldap3::{LdapConn, Scope};',
      'async fn h(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {',
      '    let uid = query.get("uid").cloned().unwrap_or_default();',
      '    let filter = format!("(uid={})", uid);',
      '    let mut ldap = LdapConn::new("ldap://x").unwrap();',
      '    let (_rs, _res) = ldap',
      '        .search("ou=u,dc=ex,dc=com", Scope::Subtree, &filter, vec!["cn"])',
      '        .unwrap()',
      '        .success()',
      '        .unwrap();',
      '    let _ = ldap.unbind();',
      '    HttpResponse::Ok().body("ok")',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/a.rs', 'rust');
    expect(hasLdapSignal(r)).toBe(true);
  });

  it('C-TN: Rust LdapConn::search with literal filter does NOT fire', async () => {
    const code = [
      'use actix_web::HttpResponse;',
      'use ldap3::{LdapConn, Scope};',
      'async fn h() -> HttpResponse {',
      '    let mut ldap = LdapConn::new("ldap://x").unwrap();',
      '    let (_rs, _res) = ldap',
      '        .search("ou=u,dc=ex,dc=com", Scope::Subtree, "(objectclass=*)", vec!["cn"])',
      '        .unwrap()',
      '        .success()',
      '        .unwrap();',
      '    HttpResponse::Ok().body("ok")',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/a.rs', 'rust');
    expect(hasLdapSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // D. Rust log injection — log crate macros with tainted args.

  it('D-TP: Rust log::info! with tainted interpolation fires', async () => {
    const code = [
      'use actix_web::{web, HttpResponse};',
      'use log::{info, warn};',
      'async fn h(query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {',
      '    let user = query.get("user").cloned().unwrap_or_default();',
      '    info!("user login attempt: {}", user);',
      '    warn!("login warning for {}", user);',
      '    HttpResponse::Ok().body("ok")',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/a.rs', 'rust');
    expect(hasLogInjSignal(r)).toBe(true);
    // At least one of info!/warn! lines should be tagged.
    expect(countRule(r, 'log_injection')).toBeGreaterThanOrEqual(1);
  });

  it('D-TN: Rust log::info! with literal-only args does NOT fire', async () => {
    const code = [
      'use log::info;',
      'fn h() {',
      '    info!("server starting");',
      '    info!("listening on :{}", 8080);',
      '}',
    ].join('\n');
    const r = await analyze(code, '/x/a.rs', 'rust');
    expect(hasLogInjSignal(r)).toBe(false);
  });

  // -------------------------------------------------------------------------
  // E. Sanity TPs for already-working log_injection language coverage.

  it('E-TP-py: Python logging with tainted concat fires log_injection', async () => {
    const code = [
      'import logging',
      'from flask import Flask, request',
      'app = Flask(__name__)',
      'logger = logging.getLogger("app")',
      '@app.route("/login")',
      'def login():',
      '    user = request.args.get("user", "")',
      '    logger.info("user login attempt: " + user)',
      '    return "ok"',
    ].join('\n');
    const r = await analyze(code, '/x/a.py', 'python');
    expect(hasLogInjSignal(r)).toBe(true);
  });

  it('E-TP-js: JS console.log with tainted concat fires log_injection', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.get('/login', (req, res) => {",
      '  const user = req.query.user;',
      "  console.log('user login attempt: ' + user);",
      "  res.send('ok');",
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasLogInjSignal(r)).toBe(true);
  });
});
