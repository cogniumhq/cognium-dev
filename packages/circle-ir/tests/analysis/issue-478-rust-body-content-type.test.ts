/**
 * cognium-dev#478 — a Rust actix-web `.body(x)` is an xss sink only when the
 * response can be rendered as markup. A literal non-HTML content type declared
 * on the same builder chain (`text/plain`, `application/json`, …) serves the
 * body as data. No content type, HTML, XML and computed types keep the sink,
 * because actix does not add a `Content-Type` for `.body(...)` itself.
 *
 * Shares its rule with the C# `Content(body, contentType)` gate (#580).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const xss = async (chain: string): Promise<string[]> => {
  const code = `use actix_web::{get, web, HttpResponse};

#[get("/echo")]
async fn show(q: web::Query<Params>) -> HttpResponse {
    let msg = q.note.clone();
    ${chain}
}
`;
  const r = await analyze(code, 'handlers.rs', 'rust');
  return (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss').map(f => `xss@${f.sink_line}`);
};

describe('#478 Rust body() with a declared content type', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('literal text/plain is clean', async () => {
    expect(await xss('HttpResponse::Ok().content_type("text/plain").body(msg)')).toEqual([]);
  });

  it('literal application/json is clean, including a serialized body', async () => {
    expect(await xss('HttpResponse::Ok().content_type("application/json").body(msg)')).toEqual([]);
    expect(await xss('HttpResponse::Ok().content_type("application/json").body(serde_json::to_string(&msg).unwrap())')).toEqual([]);
  });

  it('a charset parameter on a non-HTML literal is still clean', async () => {
    expect(await xss('HttpResponse::Ok().content_type("text/plain; charset=utf-8").body(msg)')).toEqual([]);
  });

  it('ContentType and mime constants for non-HTML types are clean', async () => {
    expect(await xss('HttpResponse::Ok().content_type(ContentType::plaintext()).body(msg)')).toEqual([]);
    expect(await xss('HttpResponse::Ok().content_type(ContentType::json()).body(msg)')).toEqual([]);
    expect(await xss('HttpResponse::Ok().content_type(mime::APPLICATION_JSON).body(msg)')).toEqual([]);
    expect(await xss('HttpResponse::Ok().content_type(mime::TEXT_PLAIN).body(msg)')).toEqual([]);
  });

  it('a chain split across lines is read the same way', async () => {
    expect(await xss('HttpResponse::Ok()\n        .content_type("text/plain")\n        .body(msg)')).toEqual([]);
  });

  it('literal text/html still fires', async () => {
    expect((await xss('HttpResponse::Ok().content_type("text/html").body(format!("<p>{}</p>", msg))')).length).toBe(1);
    expect((await xss('HttpResponse::Ok().content_type("text/html; charset=utf-8").body(msg)')).length).toBe(1);
  });

  it('ContentType::html() and mime::TEXT_HTML still fire', async () => {
    expect((await xss('HttpResponse::Ok().content_type(ContentType::html()).body(msg)')).length).toBe(1);
    expect((await xss('HttpResponse::Ok().content_type(mime::TEXT_HTML).body(msg)')).length).toBe(1);
  });

  it('no content type keeps firing', async () => {
    expect((await xss('HttpResponse::Ok().body(msg)')).length).toBe(1);
  });

  it('script-capable XML types keep firing', async () => {
    for (const t of ['text/xml', 'application/xml', 'image/svg+xml', 'application/xhtml+xml', 'application/atom+xml']) {
      expect((await xss(`HttpResponse::Ok().content_type("${t}").body(msg)`)).length).toBe(1);
    }
  });

  it('a computed content type keeps firing', async () => {
    expect((await xss('HttpResponse::Ok().content_type(kind.as_str()).body(msg)')).length).toBe(1);
    expect((await xss('HttpResponse::Ok().content_type(format!("text/{}", sub)).body(msg)')).length).toBe(1);
  });

  it('a malformed literal (no type/subtype) keeps firing', async () => {
    expect((await xss('HttpResponse::Ok().content_type("plain").body(msg)')).length).toBe(1);
  });

  it('the last content type on the chain wins', async () => {
    expect((await xss('HttpResponse::Ok().content_type("text/plain").content_type("text/html").body(msg)')).length).toBe(1);
    expect(await xss('HttpResponse::Ok().content_type("text/html").content_type("text/plain").body(msg)')).toEqual([]);
  });

  it('a content_type nested inside another argument is not the response type', async () => {
    expect((await xss('HttpResponse::Ok().insert_header(("X-Meta", other.content_type("text/plain"))).body(msg)')).length).toBe(1);
  });
});
