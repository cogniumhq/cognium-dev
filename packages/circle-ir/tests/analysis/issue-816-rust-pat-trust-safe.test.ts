/**
 * cognium-dev #816 — PAT-TRUST-01 Rust safe mirror (cve-intake-b).
 * Const slice membership guard before actix-session insert.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const tbFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter(f => f.sink_type === 'trust_boundary' && !f.sanitized);

const safeThemeRoute = `use actix_web::{web, HttpResponse};
use actix_session::Session;

const THEMES: &[&str] = &["light", "dark"];

async fn set_theme(session: Session, q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let theme = q.get("theme").cloned().unwrap_or_default();
    if !THEMES.contains(&theme.as_str()) {
        return HttpResponse::BadRequest().finish();
    }
    session.insert("theme", theme).unwrap();
    HttpResponse::Ok().finish()
}
`;

const rawThemeRoute = `use actix_web::{web, HttpResponse};
use actix_session::Session;

async fn set_theme_raw(session: Session, q: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let theme = q.get("theme").cloned().unwrap_or_default();
    session.insert("theme", theme).unwrap();
    HttpResponse::Ok().finish()
}
`;

describe('#816 PAT-TRUST-01 rust safe mirror', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('membership-checked theme stays clean on session.insert', async () => {
    const ir = await analyze(safeThemeRoute, 'pat_trust_safe.rs', 'rust');
    expect(tbFlows(ir)).toEqual([]);
  });

  it('recall: raw theme in session.insert still emits trust_boundary', async () => {
    const ir = await analyze(rawThemeRoute, 'pat_trust_tp.rs', 'rust');
    expect(tbFlows(ir).length).toBeGreaterThan(0);
  });
});
