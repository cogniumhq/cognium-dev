/**
 * cognium-dev #686 — JSX `dangerouslySetInnerHTML` on a destructured React
 * component prop: sink is found but the param-source gate drops the flow.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { SupportedLanguage } from '../../src/types/index.js';

async function xssFlows(code: string, file: string, lang: SupportedLanguage) {
  const ir = await analyze(code, file, lang);
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss');
}

beforeAll(async () => {
  await initAnalyzer();
});

describe('#686 React component prop → dangerouslySetInnerHTML', () => {
  it('javascript: HtmlPreview reports an xss flow', async () => {
    const code = `export function HtmlPreview({ markup }) {
  return <div dangerouslySetInnerHTML={{ __html: markup }} />;
}
`;
    const flows = await xssFlows(code, 'HtmlPreview.jsx', 'javascript');
    expect(flows.length).toBe(1);
    expect(flows[0].sink_line).toBe(2);
  });

  it('typescript: TypedPreview reports an xss flow', async () => {
    const code = `export function TypedPreview({ markup }: { markup: string }) {
  return <div dangerouslySetInnerHTML={{ __html: markup }} />;
}
`;
    const flows = await xssFlows(code, 'TypedPreview.tsx', 'typescript');
    expect(flows.length).toBe(1);
    expect(flows[0].sink_line).toBe(2);
  });

  it('SanitizedPreview stays clean', async () => {
    const code = `import DOMPurify from 'dompurify';
export function SanitizedPreview({ markup }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(markup) }} />;
}
`;
    expect(await xssFlows(code, 'SanitizedPreview.jsx', 'javascript')).toHaveLength(0);
  });

  it('StaticPreview with literal __html stays clean', async () => {
    const code = `export function StaticPreview({ markup }) {
  return <div dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} />;
}
`;
    expect(await xssFlows(code, 'StaticPreview.jsx', 'javascript')).toHaveLength(0);
  });

  it('TextPreview without dangerouslySetInnerHTML stays clean', async () => {
    const code = `export function TextPreview({ markup }) {
  return <div>{markup}</div>;
}
`;
    expect(await xssFlows(code, 'TextPreview.jsx', 'javascript')).toHaveLength(0);
  });

  it('DomWriter innerHTML in component stays gated (sink only, no flow)', async () => {
    const code = `export function DomWriter({ markup }) {
  document.getElementById('out').innerHTML = markup;
  return null;
}
`;
    const flows = await xssFlows(code, 'DomWriter.jsx', 'javascript');
    expect(flows).toHaveLength(0);
  });

  it('lower-case renderHtml helper stays gated', async () => {
    const code = `function renderHtml({ markup }) {
  return <div dangerouslySetInnerHTML={{ __html: markup }} />;
}
`;
    expect(await xssFlows(code, 'helperRender.jsx', 'javascript')).toHaveLength(0);
  });
});
