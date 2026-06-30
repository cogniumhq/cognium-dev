/**
 * Sprint 78 (combined 78+79+80) — #190 Tier-2 config-pattern regression.
 *
 * Engine inventory on 3.128.0 found 6 of the 14 pinned TP cells already
 * detected (go-insecure-cookie, py-cors, py-xfo-csp, py-tls, rust-tls,
 * bash-md5). This sprint adds 8 new per-language pattern detectors to
 * close the remaining gap:
 *
 *   1. rust hardcoded_secrets api_key      `pub const API_KEY: &str = "..."`
 *   2. rust insecure_cookie no_flags       `Cookie::build(...).secure(false).http_only(false)`
 *   3. java jwt_verify_disabled            `JWT.decode(token)` (auth0 — no .verify)
 *   4. rust jwt_verify_disabled            `validation.insecure_disable_signature_validation()`
 *   5. java tls_verify_disabled            anonymous X509TrustManager with empty body
 *   6. go   weak_crypto ecb_mode           `aes.NewCipher(...)` + raw `.Encrypt(...)`
 *   7. rust weak_crypto ecb_mode           `Aes128::new(...).encrypt_block(...)` raw
 *   8. js   xml_entity_expansion           `libxmljs.parseXml(buf, { noent: true })`
 *
 * Each TP-FN reproduces the verbatim corpus fixture (must fire the
 * configured rule_id). Each TN-control proves the detector does not
 * over-fire on the obvious benign variant (verify chain, secure flags,
 * GCM mode, noent:false, etc.).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countRule = (r: any, id: string) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === id).length;

describe('#190 Sprint 78 — Tier-2 misconfig detectors (8 cells)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // 1. rust hardcoded-credential — const literal assignment
  // -------------------------------------------------------------------------
  it('FN-1 rust hardcoded-credential — pub const API_KEY: &str = "..." must fire', async () => {
    const code = 'pub const API_KEY: &str = "sk-live-abcdef1234567890abcdef1234567890";\n';
    const r = await analyze(code, 'v01_api_key_tp.rs', 'rust');
    expect(countRule(r, 'hardcoded-credential')).toBeGreaterThanOrEqual(1);
  });

  it('TN-1 rust hardcoded-credential — non-secret const must NOT fire', async () => {
    const code = 'pub const MAX_RETRIES: u32 = 5;\npub const APP_NAME: &str = "demo";\n';
    const r = await analyze(code, 'tn_const_benign.rs', 'rust');
    expect(countRule(r, 'hardcoded-credential')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 2. rust insecure-cookie — Cookie::build chain with secure(false)+http_only(false)
  // -------------------------------------------------------------------------
  it('FN-2 rust insecure-cookie — Cookie::build(...).secure(false).http_only(false) must fire', async () => {
    const code = [
      'use actix_web::HttpResponse;',
      'pub fn set_session(sid: &str) -> HttpResponse {',
      '    HttpResponse::Ok()',
      '        .cookie(actix_web::cookie::Cookie::build("SESSIONID", sid).secure(false).http_only(false).finish())',
      '        .finish()',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_no_flags_tp.rs', 'rust');
    expect(countRule(r, 'insecure-cookie')).toBeGreaterThanOrEqual(1);
  });

  it('TN-2 rust insecure-cookie — Cookie::build(...).secure(true).http_only(true) must NOT fire', async () => {
    const code = [
      'use actix_web::HttpResponse;',
      'pub fn set_session(sid: &str) -> HttpResponse {',
      '    HttpResponse::Ok()',
      '        .cookie(actix_web::cookie::Cookie::build("SESSIONID", sid).secure(true).http_only(true).finish())',
      '        .finish()',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_cookie_secure.rs', 'rust');
    expect(countRule(r, 'insecure-cookie')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 3. java jwt-verify-disabled — auth0 JWT.decode(token) bare call
  // -------------------------------------------------------------------------
  it('FN-3 java jwt-verify-disabled — JWT.decode(token) without .verify must fire', async () => {
    const code = [
      'package com.demo.config.jwt_verify_disabled;',
      'import com.auth0.jwt.JWT;',
      'import com.auth0.jwt.interfaces.DecodedJWT;',
      'public class V01NoVerifyTp {',
      '    public DecodedJWT decode(String token) {',
      '        return JWT.decode(token);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'V01NoVerifyTp.java', 'java');
    expect(countRule(r, 'jwt-verify-disabled')).toBeGreaterThanOrEqual(1);
  });

  it('TN-3 java jwt-verify-disabled — JWT.require(...).build().verify(token) must NOT fire', async () => {
    const code = [
      'package com.demo.config.jwt_verify_enabled;',
      'import com.auth0.jwt.JWT;',
      'import com.auth0.jwt.algorithms.Algorithm;',
      'import com.auth0.jwt.interfaces.DecodedJWT;',
      'public class V01VerifyTn {',
      '    public DecodedJWT decode(String token, String secret) {',
      '        return JWT.require(Algorithm.HMAC256(secret)).build().verify(token);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'V01VerifyTn.java', 'java');
    expect(countRule(r, 'jwt-verify-disabled')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 4. rust jwt-verify-disabled — jsonwebtoken insecure_disable_signature_validation
  // -------------------------------------------------------------------------
  it('FN-4 rust jwt-verify-disabled — insecure_disable_signature_validation() must fire', async () => {
    const code = [
      'use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};',
      'pub fn decode_token(token: &str) -> Result<serde_json::Value, jsonwebtoken::errors::Error> {',
      '    let mut validation = Validation::new(Algorithm::HS256);',
      '    validation.insecure_disable_signature_validation();',
      '    decode::<serde_json::Value>(token, &DecodingKey::from_secret(b"x"), &validation).map(|d| d.claims)',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_no_verify_tp.rs', 'rust');
    expect(countRule(r, 'jwt-verify-disabled')).toBeGreaterThanOrEqual(1);
  });

  it('TN-4 rust jwt-verify-disabled — Validation::new(HS256) with no disable call must NOT fire', async () => {
    const code = [
      'use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};',
      'pub fn decode_token(token: &str) -> Result<serde_json::Value, jsonwebtoken::errors::Error> {',
      '    let validation = Validation::new(Algorithm::HS256);',
      '    decode::<serde_json::Value>(token, &DecodingKey::from_secret(b"x"), &validation).map(|d| d.claims)',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_jwt_verify.rs', 'rust');
    expect(countRule(r, 'jwt-verify-disabled')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 5. java tls-verify-disabled — anonymous X509TrustManager with empty body
  // -------------------------------------------------------------------------
  it('FN-5 java tls-verify-disabled — anonymous X509TrustManager with empty checkServerTrusted must fire', async () => {
    const code = [
      'package com.demo.config.tls_verify_disabled;',
      'import javax.net.ssl.*;',
      'public class V01SkipVerifyTp {',
      '    public SSLContext ctx() throws Exception {',
      '        SSLContext sc = SSLContext.getInstance("TLS");',
      '        sc.init(null, new TrustManager[]{new X509TrustManager() {',
      '            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}',
      '            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}',
      '            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }',
      '        }}, new java.security.SecureRandom());',
      '        return sc;',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'V01SkipVerifyTp.java', 'java');
    expect(countRule(r, 'tls-verify-disabled')).toBeGreaterThanOrEqual(1);
  });

  it('TN-5 java tls-verify-disabled — default SSLContext.getDefault() must NOT fire', async () => {
    const code = [
      'package com.demo.config.tls_verify_enabled;',
      'import javax.net.ssl.SSLContext;',
      'public class V01VerifyTn {',
      '    public SSLContext ctx() throws Exception {',
      '        return SSLContext.getDefault();',
      '    }',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'V01VerifyTn.java', 'java');
    expect(countRule(r, 'tls-verify-disabled')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 6. go weak-crypto ECB — aes.NewCipher + raw .Encrypt without mode wrapper
  // -------------------------------------------------------------------------
  it('FN-6 go weak-crypto — aes.NewCipher + raw c.Encrypt (single-block ECB) must fire', async () => {
    const code = [
      'package main',
      'import "crypto/aes"',
      'func EncECB(key, data []byte) []byte {',
      '    c, _ := aes.NewCipher(key)',
      '    out := make([]byte, len(data))',
      '    c.Encrypt(out, data)',
      '    return out',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_ecb_mode_tp.go', 'go');
    expect(countRule(r, 'weak-crypto')).toBeGreaterThanOrEqual(1);
  });

  it('TN-6 go weak-crypto — cipher.NewGCM(c) wrapped (no raw Encrypt) must NOT fire', async () => {
    const code = [
      'package main',
      'import (',
      '    "crypto/aes"',
      '    "crypto/cipher"',
      ')',
      'func EncGCM(key, nonce, data []byte) ([]byte, error) {',
      '    c, _ := aes.NewCipher(key)',
      '    g, _ := cipher.NewGCM(c)',
      '    return g.Seal(nil, nonce, data, nil), nil',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_aes_gcm.go', 'go');
    expect(countRule(r, 'weak-crypto')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 7. rust weak-crypto ECB — Aes128::new + raw encrypt_block
  // -------------------------------------------------------------------------
  it('FN-7 rust weak-crypto — Aes128::new + encrypt_block (raw ECB) must fire', async () => {
    const code = [
      'use aes::Aes128;',
      'use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};',
      'pub fn ecb_encrypt(key: &[u8; 16], block: &mut [u8; 16]) {',
      '    let c = Aes128::new(GenericArray::from_slice(key));',
      '    c.encrypt_block(GenericArray::from_mut_slice(block));',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_ecb_mode_tp.rs', 'rust');
    expect(countRule(r, 'weak-crypto')).toBeGreaterThanOrEqual(1);
  });

  it('TN-7 rust weak-crypto — aes-gcm Aes128Gcm Seal must NOT fire', async () => {
    const code = [
      'use aes_gcm::aead::{Aead, KeyInit};',
      'use aes_gcm::{Aes128Gcm, Key, Nonce};',
      'pub fn gcm_encrypt(key: &[u8; 16], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {',
      '    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));',
      '    cipher.encrypt(Nonce::from_slice(nonce), data).unwrap()',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_aes_gcm.rs', 'rust');
    expect(countRule(r, 'weak-crypto')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 8. js xml-entity-expansion — libxmljs.parseXml with noent:true
  // -------------------------------------------------------------------------
  it('FN-8 js xml-entity-expansion — libxmljs.parseXml(buf, { noent: true }) must fire', async () => {
    const code = [
      'const libxml = require("libxmljs");',
      'function parse(buf) { return libxml.parseXml(buf, { noent: true }); }',
      'module.exports = { parse };',
      '',
    ].join('\n');
    const r = await analyze(code, 'v01_resolve_entities_tp.js', 'javascript');
    expect(countRule(r, 'xml-entity-expansion')).toBeGreaterThanOrEqual(1);
  });

  it('TN-8 js xml-entity-expansion — libxmljs.parseXml(buf, { noent: false }) must NOT fire', async () => {
    const code = [
      'const libxml = require("libxmljs");',
      'function parse(buf) { return libxml.parseXml(buf, { noent: false }); }',
      'module.exports = { parse };',
      '',
    ].join('\n');
    const r = await analyze(code, 'tn_noent_false.js', 'javascript');
    expect(countRule(r, 'xml-entity-expansion')).toBe(0);
  });
});
