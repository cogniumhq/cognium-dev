/**
 * Django RawSQL sink coverage (framework-coverage expansion).
 *
 * `django.db.models.expressions.RawSQL(sql, params)` embeds arg[0] verbatim
 * into the query. Concatenating user input into that fragment is CWE-89.
 * Parameterised use passes input through arg[1] (`RawSQL("... %s", [uid])`),
 * keeping it out of arg[0] — so a flow fires only on concatenation.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('Django RawSQL sink (CWE-89)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sqlFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection');

  it('RawSQL with concatenated input flows', async () => {
    const code = [
      'from django.db.models.expressions import RawSQL',
      'def view(request):',
      '    uid = request.GET.get("id")',
      '    return Model.objects.annotate(x=RawSQL("SELECT x WHERE id=" + uid, []))',
    ].join('\n');
    const r = await analyze(code, 'views.py', 'python');
    expect(r.taint.sinks.some((s) => s.method === 'RawSQL' && s.cwe === 'CWE-89')).toBe(true);
    expect(sqlFlows(r).length).toBeGreaterThan(0);
  });

  it('parameterised RawSQL (%s placeholder + params list) does NOT flow', async () => {
    const code = [
      'from django.db.models.expressions import RawSQL',
      'def view(request):',
      '    uid = request.GET.get("id")',
      '    return Model.objects.annotate(x=RawSQL("SELECT x WHERE id=%s", [uid]))',
    ].join('\n');
    const r = await analyze(code, 'views.py', 'python');
    // The SQL string is a constant literal; user input reaches only arg[1].
    expect(sqlFlows(r).length).toBe(0);
  });

  it('is python-scoped — a Java RawSQL-named call is unaffected', async () => {
    const code = [
      'public class Svc {',
      '  void run(String id) {',
      '    RawSQL("SELECT x WHERE id=" + id, null);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Svc.java', 'java');
    expect(sqlFlows(r).length).toBe(0);
  });
});
