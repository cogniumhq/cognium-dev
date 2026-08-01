/**
 * Remaining Python FP guards (cognium-dev #4 residual-FP audit, slice 5):
 * string-literal validation, default-configured SAX parser, and URL host
 * allowlist. Together these cleared the last 13 flow-level FPs on OWASP
 * BenchmarkPython (codeinj 7, xxe 3, redirect 3).
 *
 * The XXE one is the delicate case: in that corpus the vulnerable and safe
 * files call the *same* API and differ only by a `setFeature(...external_ges,
 * True)` line, so the "still fires" test below is what keeps all 8 true
 * positives alive.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

async function unsanitizedFlows(code: string, sinkType: string): Promise<number> {
  const ir = await analyze(code, 'app.py', 'python');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === sinkType && !f.sanitized).length;
}

const head = ['from flask import request', 'def handler():', '    bar = request.args.get("p")'];

describe('python string-literal validation guard (code_injection)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const guard = [
    `    if not bar.startswith('\\'') or not bar.endswith('\\'') or '\\'' in bar[1:-1]:`,
    '        return "must be a plain string literal"',
  ];

  it('suppresses exec() past the full three-clause guard', async () => {
    expect(await unsanitizedFlows([...head, ...guard, '    exec(bar)'].join('\n'), 'code_injection')).toBe(0);
  });

  it('still fires when the interior-quote clause is missing', async () => {
    // `'a' + evil() + '` satisfies startswith/endswith yet breaks out.
    const partial = [
      `    if not bar.startswith('\\'') or not bar.endswith('\\''):`,
      '        return "nope"',
    ];
    expect(
      await unsanitizedFlows([...head, ...partial, '    exec(bar)'].join('\n'), 'code_injection'),
    ).toBeGreaterThan(0);
  });

  it('still fires when the guard does not leave the function', async () => {
    const noReturn = [
      `    if not bar.startswith('\\'') or not bar.endswith('\\'') or '\\'' in bar[1:-1]:`,
      '        log("suspicious")',
    ];
    expect(
      await unsanitizedFlows([...head, ...noReturn, '    exec(bar)'].join('\n'), 'code_injection'),
    ).toBeGreaterThan(0);
  });
});

describe('python default-configured SAX parser (xxe)', () => {
  const body = (extra: string[]): string =>
    [
      'from flask import request',
      'import xml.dom.minidom',
      'import xml.sax',
      'import xml.sax.handler',
      'def handler():',
      '    bar = request.args.get("p")',
      '    parser = xml.sax.make_parser()',
      ...extra,
      '    doc = xml.dom.minidom.parseString(bar, parser)',
    ].join('\n');

  it('suppresses XXE for a parser left at its defaults', async () => {
    expect(await unsanitizedFlows(body([]), 'xxe')).toBe(0);
  });

  it('STILL FIRES when external general entities are enabled', async () => {
    expect(
      await unsanitizedFlows(
        body(['    parser.setFeature(xml.sax.handler.feature_external_ges, True)']),
        'xxe',
      ),
    ).toBeGreaterThan(0);
  });

  it('still fires when a custom entity resolver is installed', async () => {
    expect(
      await unsanitizedFlows(body(['    parser.setEntityResolver(MyResolver())']), 'xxe'),
    ).toBeGreaterThan(0);
  });
});

describe('python URL host allowlist guard (open_redirect)', () => {
  const body = (guardLine: string): string =>
    [
      'from flask import request',
      'import flask',
      'import urllib.parse',
      'def handler():',
      '    bar = request.args.get("p")',
      '    url = urllib.parse.urlparse(bar)',
      guardLine,
      '        return "Invalid URL."',
      '    return flask.redirect(bar)',
    ].join('\n');

  it('suppresses the redirect past a netloc allowlist check', async () => {
    expect(
      await unsanitizedFlows(
        body("    if url.netloc not in ['example.com'] or url.scheme != 'https':"),
        'open_redirect',
      ),
    ).toBe(0);
  });

  it('still fires for a path-only check that leaves the host open', async () => {
    expect(
      await unsanitizedFlows(body("    if url.path not in ['/ok']:"), 'open_redirect'),
    ).toBeGreaterThan(0);
  });
});
