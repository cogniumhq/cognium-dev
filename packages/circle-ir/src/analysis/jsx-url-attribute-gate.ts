/**
 * JSX URL attributes are XSS sinks for browser and URL input only.
 *
 * `<a href={x}>`, `<iframe src={x}>` and `<script src={x}>` run a
 * `javascript:` URL, so a URL the attacker writes is CWE-79. The value is far
 * more often the app's own data (a prop, state built from constants, an API
 * field), and React does not block `javascript:` URLs, so flagging every
 * tainted value would bury the real cases. A flow into one of these sinks is
 * kept only when:
 *
 *   - its source line carries browser or URL input (the query string, hash or
 *     path, the referrer, route parameters, a `postMessage` payload, DOM input
 *     or browser storage), and
 *   - the enclosing function does not check the URL: no call named like a URL
 *     check (`isSafeUrl(u)`, `sanitizeUrl(u)`, `validateUrl(u)`), no
 *     `.protocol` test, no `^https?:` pattern and no `startsWith('http…')`.
 *
 * `encodeURI` / `encodeURIComponent` are XSS sanitizers in the registry and
 * already end the flow.
 */

import type { MethodInfo, SourceType, TaintFlowInfo, TaintSink, TaintSource, TypeInfo } from '../types/index.js';
import { JSX_URL_ATTRIBUTE_RECEIVER } from '../core/extractors/calls.js';

const BROWSER_OR_URL_SOURCES: ReadonlySet<SourceType> = new Set<SourceType>([
  'http_param',
  'http_query',
  'http_path',
  'http_header',
  'http_cookie',
  'url_param',
  'navigation_param',
  'message_input',
  'dom_input',
  'storage_input',
  'user_input',
]);

/** A URL check in the function that renders the attribute. */
const URL_CHECK =
  /\b(?:is|sanitize|safe|valid|validate|allow|allowed|check|assert|ensure|clean)[A-Za-z]*U(?:rl|RL|ri|RI)[A-Za-z]*\s*\(|\.protocol\b|\^https\?:|\bstartsWith\(\s*['"`]https?:/;

function enclosing(methods: MethodInfo[], line: number): MethodInfo | undefined {
  let best: MethodInfo | undefined;
  for (const m of methods) {
    if (m.start_line <= line && line <= m.end_line && (!best || m.start_line >= best.start_line)) best = m;
  }
  return best;
}

/**
 * Drop flows into JSX URL attribute sinks that do not come from browser or URL
 * input, or that the rendering function checks. Flows to a line that also
 * holds another XSS sink are left alone.
 */
export function gateJsxUrlAttributeFlows(
  taint: { sources: TaintSource[]; sinks: TaintSink[]; flows?: TaintFlowInfo[] },
  types: TypeInfo[],
  code: string,
): void {
  if (!taint.flows || taint.flows.length === 0) return;
  const xssSinks = taint.sinks.filter((s) => s.type === 'xss');
  const otherXssLines = new Set(xssSinks.filter((s) => s.class !== JSX_URL_ATTRIBUTE_RECEIVER).map((s) => s.line));
  const urlSinkLines = new Set(
    xssSinks.filter((s) => s.class === JSX_URL_ATTRIBUTE_RECEIVER && !otherXssLines.has(s.line)).map((s) => s.line),
  );
  if (urlSinkLines.size === 0) return;

  const lines = code.split('\n');
  const methods = types.flatMap((t) => t.methods);
  const checked = (sinkLine: number): boolean => {
    const m = enclosing(methods, sinkLine);
    const text = m ? lines.slice(m.start_line - 1, m.end_line).join('\n') : lines[sinkLine - 1] ?? '';
    return URL_CHECK.test(text);
  };
  const browserInputAt = (line: number): boolean =>
    taint.sources.some((s) => s.line === line && BROWSER_OR_URL_SOURCES.has(s.type));

  taint.flows = taint.flows.filter((f) => {
    if (f.sink_type !== 'xss' || !urlSinkLines.has(f.sink_line)) return true;
    return (BROWSER_OR_URL_SOURCES.has(f.source_type) || browserInputAt(f.source_line)) && !checked(f.sink_line);
  });
}
