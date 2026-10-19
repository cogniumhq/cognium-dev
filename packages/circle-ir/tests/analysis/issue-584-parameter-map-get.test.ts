/**
 * #584 (slice) — TP guard: `request.getParameterMap().get(...)` must still seed
 * `http_param` and reach sinks. Literal-only local `Map.get` reads stay clean (#328/#832).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const httpFlows = (r: IR) =>
  (r.taint.flows ?? []).filter(f => f.source_type === 'http_param');
const xssFlows = (r: IR) => httpFlows(r).filter(f => f.sink_type === 'xss');

const servlet = (body: string[]) =>
  analyze(
    [
      'import java.io.IOException;',
      'import java.util.Map;',
      'import javax.servlet.http.*;',
      'public class ParamMapProbe extends HttpServlet {',
      '  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {',
      ...body.map(l => '    ' + l),
      '  }',
      '}',
    ].join('\n'),
    'ParamMapProbe.java',
    'java',
  );

describe('#584 request.getParameterMap().get TP guard', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('chained getParameterMap().get("k") into println reports http_param xss', async () => {
    const r = await servlet([
      'String[] vals = request.getParameterMap().get("k");',
      'response.getWriter().println(vals[0]);',
    ]);
    expect(xssFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('literal-only local map get stays clean (control)', async () => {
    const r = await servlet([
      'java.util.HashMap<String, String> m = new java.util.HashMap<>();',
      'm.put("title", "Welcome");',
      'response.getWriter().println(m.get("title"));',
    ]);
    expect(xssFlows(r)).toHaveLength(0);
    expect(
      (r.taint.sources ?? []).filter(s => s.type === 'plugin_param' && /\.get\(\)/.test(s.location ?? '')),
    ).toHaveLength(0);
  });
});
