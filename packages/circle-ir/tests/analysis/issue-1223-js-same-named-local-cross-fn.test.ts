/**
 * cognium-dev#1223 — a tainted local named `query` in one export must not
 * taint `req.query.*` in another function via identifier-name matching.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const DVNA_REPRO = `module.exports.search = function (req, res) {
  var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'"
  res.send(query.length)
}
module.exports.redirect = function (req, res) {
  if (req.query.url) {
    res.redirect(req.query.url)
  }
}
`;

const DVNA_REPRO_RENAMED = `module.exports.search = function (req, res) {
  var q = "SELECT name FROM Users WHERE login='" + req.body.login + "'"
  res.send(q.length)
}
module.exports.redirect = function (req, res) {
  if (req.query.url) {
    res.redirect(req.query.url)
  }
}
`;

const crossBodyToRedirect = (flows: Awaited<ReturnType<typeof analyze>>['taint']['flows']) =>
  (flows ?? []).filter(
    (f) => f.source_type === 'http_body' && (f.sink_type === 'open_redirect' || f.sink_type === 'crlf'),
  );

describe('#1223 JS same-named local does not cross functions', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('keeps only http_param flows on redirect when search taints a local named query', async () => {
    const r = await analyze(DVNA_REPRO, 'appHandler.js', 'javascript');
    expect(crossBodyToRedirect(r.taint.flows)).toEqual([]);
    const paramFlows = (r.taint.flows ?? []).filter(
      (f) => f.source_type === 'http_param' && f.sink_type === 'open_redirect',
    );
    expect(paramFlows.length).toBeGreaterThanOrEqual(1);
    expect(paramFlows.every((f) => f.source_line === f.sink_line)).toBe(true);
  });

  it('still reports http_param → open_redirect when the local is renamed', async () => {
    const r = await analyze(DVNA_REPRO_RENAMED, 'appHandler.js', 'javascript');
    const paramFlows = (r.taint.flows ?? []).filter(
      (f) => f.source_type === 'http_param' && f.sink_type === 'open_redirect',
    );
    expect(paramFlows.length).toBeGreaterThanOrEqual(1);
  });
});
