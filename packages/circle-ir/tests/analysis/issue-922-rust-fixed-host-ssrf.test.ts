import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

beforeAll(async () => {
  await initAnalyzer();
});

function ssrfFlows(code: string, file = 'RustTest00024.rs') {
  return analyze(code, file, 'rust').then((r) =>
    (r.taint.flows ?? []).filter((f) => f.sink_type === 'ssrf' && !f.sanitized),
  );
}

describe('issue #922 rust fixed-host ssrf', () => {
  it('constant origin with interpolated path segment is not ssrf', async () => {
    const code = `
use actix_web::{web, HttpResponse, Responder};

pub async fn fetch(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let segment = query.get("q").cloned().unwrap_or_default();
    let url = format!("http://internal-api.local:8080/{}", segment);
    let resp = reqwest::get(&url).await;
    match resp {
        Ok(r) => HttpResponse::Ok().body(r.text().await.unwrap_or_default()),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
`;
    expect(await ssrfFlows(code)).toHaveLength(0);
  });

  it('variable host in format! still fires ssrf', async () => {
    const code = `
use actix_web::{web, HttpResponse, Responder};

pub async fn fetch(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let host = query.get("host").cloned().unwrap_or_default();
    let url = format!("https://{}/data", host);
    let resp = reqwest::get(&url).await;
    match resp {
        Ok(r) => HttpResponse::Ok().body(r.text().await.unwrap_or_default()),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
`;
    const flows = await ssrfFlows(code, 'bad.rs');
    expect(flows.length).toBeGreaterThan(0);
  });

  // CWE-Bench-Rust RustTest00024 shape: the origin comes from a file-level const.
  const constHost = (decl: string, fmt: string) => `
use actix_web::{web, HttpRequest, HttpResponse};

${decl}

async fn internal_fetch(req: HttpRequest) -> HttpResponse {
    let resource_id = req.query_string();
    let url = format!(${fmt}, INTERNAL_API_BASE, resource_id);
    let response = reqwest::get(&url).await.unwrap();
    let body = response.text().await.unwrap();
    HttpResponse::Ok().body(body)
}
`;

  it('const origin as the first format! argument, path after it, is not ssrf', async () => {
    const code = constHost('const INTERNAL_API_BASE: &str = "http://internal-api.local:8080";', '"{}/resources/{}"');
    expect(await ssrfFlows(code)).toHaveLength(0);
  });

  it('static origin with a trailing path in the const is not ssrf', async () => {
    const code = constHost('pub static INTERNAL_API_BASE: &\'static str = "https://api.example.com/v1/";', '"{}{}"');
    expect(await ssrfFlows(code)).toHaveLength(0);
  });

  it('const origin with no path separator after it still fires (host can be extended)', async () => {
    const code = constHost('const INTERNAL_API_BASE: &str = "http://internal-api";', '"{}{}"');
    expect((await ssrfFlows(code, 'bad.rs')).length).toBeGreaterThan(0);
  });

  it('const that is not an origin still fires', async () => {
    const code = constHost('const INTERNAL_API_BASE: &str = "http";', '"{}://{}/x"');
    expect((await ssrfFlows(code, 'bad.rs')).length).toBeGreaterThan(0);
  });

  it('a non-const first argument still fires', async () => {
    const code = `
use actix_web::{web, HttpRequest, HttpResponse};

async fn proxy(req: HttpRequest) -> HttpResponse {
    let base = req.query_string();
    let url = format!("{}/resources/{}", base, "x");
    let response = reqwest::get(&url).await.unwrap();
    HttpResponse::Ok().body(response.text().await.unwrap())
}
`;
    expect((await ssrfFlows(code, 'bad.rs')).length).toBeGreaterThan(0);
  });
});
