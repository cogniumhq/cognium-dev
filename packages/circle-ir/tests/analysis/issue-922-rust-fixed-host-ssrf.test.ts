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
});
