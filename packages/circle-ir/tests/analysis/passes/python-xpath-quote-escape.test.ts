/**
 * Inline XPath quote-escape (cognium-dev #4 residual-FP audit, slice 3).
 *
 *   nodes = select(root, f"/Employees/Employee[@emplid='{bar.replace('\'', '&apos;')}']")
 *
 * An XPath predicate delimits its operand with a quote, so a value that cannot
 * contain that quote cannot break out and alter the expression.
 * `buildPythonSanitizedVars` already credited the *assignment* form
 * (`query = f"…{bar.replace(…)}…"` then `select(root, query)`); the inline
 * form at the sink call was not, and accounted for 8 of the 18 xpathi FPs.
 *
 * The negative cases are the point: a partial escape, a replacement that
 * reintroduces a quote, and a non-quote search token must all keep firing.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

const head = [
  'from flask import request',
  'import elementpath',
  'import xml.etree.ElementTree as ET',
  'def handler():',
  '    bar = request.args.get("q")',
  '    root = ET.parse("employees.xml")',
];

async function xpathSinks(sinkLine: string): Promise<number> {
  const ir = await analyze([...head, `    ${sinkLine}`].join('\n'), 'app.py', 'python');
  return ir.taint.sinks.filter(s => s.type === 'xpath_injection').length;
}

describe('inline XPath quote-escape', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('suppresses the sink when the tainted value is quote-escaped inline', async () => {
    expect(
      await xpathSinks(
        `nodes = elementpath.select(root, f"/E/Employee[@id='{bar.replace('\\'', '&apos;')}']")`,
      ),
    ).toBe(0);
  });

  it('accepts the double-quote form', async () => {
    expect(
      await xpathSinks(
        `nodes = elementpath.select(root, f'/E/Employee[@id="{bar.replace("\\"", "&quot;")}"]')`,
      ),
    ).toBe(0);
  });

  it('still fires when the raw value also appears on the line', async () => {
    expect(
      await xpathSinks(
        `nodes = elementpath.select(root, f"/E/Employee[@id='{bar.replace('\\'', '&apos;')}' or @n='{bar}']")`,
      ),
    ).toBeGreaterThan(0);
  });

  it("still fires when the replacement reintroduces a quote (SQL-style doubling)", async () => {
    // `.replace("'", "''")` is the SQL escaping idiom, not an XPath one — the
    // value can still carry a quote, so the predicate is still breakable.
    expect(
      await xpathSinks(
        `nodes = elementpath.select(root, "/E/Employee[@id='" + bar.replace("'", "''") + "']")`,
      ),
    ).toBeGreaterThan(0);
  });

  it('still fires when the replaced token is not a quote', async () => {
    expect(
      await xpathSinks(
        `nodes = elementpath.select(root, "/E/Employee[@id='" + bar.replace("x", "y") + "']")`,
      ),
    ).toBeGreaterThan(0);
  });

  it('still fires with no escaping at all', async () => {
    expect(
      await xpathSinks(`nodes = elementpath.select(root, f"/E/Employee[@id='{bar}']")`),
    ).toBeGreaterThan(0);
  });
});
