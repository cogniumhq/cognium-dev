/**
 * cognium-dev#1138 — decision A: keep env_input → ssrf findings, cap severity below high.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { calculateSeverity } from '../../src/analysis/rules.js';

const ENV_FETCH = `
const baseUrl = process.env.LLM_BASE_URL || 'http://localhost:4000/v1';
export async function listModels() {
  const response = await fetch(\`\${baseUrl}/models\`, { method: 'GET' });
  return response.json();
}
`;

function findingsFor(code: string, file: string, lang: 'typescript' | 'javascript' = 'typescript') {
  return analyze(code, file, lang).then((r) =>
    generateFindings(
      r.taint.sources,
      r.taint.sinks,
      r.dfg,
      file,
      code,
      lang,
      r.taint.sanitizers ?? [],
      r.types ?? [],
      r.taint.flows ?? [],
    ),
  );
}

describe('issue-1138 env_input ssrf severity cap', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('calculateSeverity caps env_input → ssrf at medium even with a confirmed path', () => {
    expect(
      calculateSeverity({
        sourceType: 'env_input',
        sinkType: 'ssrf',
        pathExists: true,
        confidence: 0.95,
      }),
    ).toBe('medium');
  });

  it('end-to-end: process.env base URL into fetch is medium SSRF, not high', async () => {
    const findings = await findingsFor(ENV_FETCH, 'config.ts');
    const ssrf = findings.filter(
      (f) => f.type === 'ssrf' && f.source.type === 'env_input',
    );
    expect(ssrf.length).toBeGreaterThan(0);
    for (const f of ssrf) {
      expect(f.severity).toBe('medium');
    }
  });

  it('http_param → ssrf stays high with a flow-backed path (control)', async () => {
    const code = `
import express from 'express';
const app = express();
app.get('/r', async (req, res) => {
  const u = req.query.url as string;
  const r = await fetch(u);
  res.json(await r.json());
});
`;
    const findings = await findingsFor(code, 'handler.ts');
    const ssrf = findings.filter(
      (f) => f.type === 'ssrf' && f.source.type === 'http_param',
    );
    expect(ssrf.some((f) => f.severity === 'high' || f.severity === 'critical')).toBe(true);
  });
});
