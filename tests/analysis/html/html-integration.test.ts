/**
 * Integration tests for HTML analysis via analyze()
 *
 * These tests call the full analyze() pipeline with HTML input
 * and verify end-to-end behavior.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, resetAnalyzer } from '../../../src/analyzer.js';

beforeAll(async () => {
  resetAnalyzer();
  await initAnalyzer();
});

describe('HTML Integration', () => {
  it('should analyze HTML with inline script', async () => {
    const html = `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
  <script>
    var x = document.getElementById("test");
    console.log(x);
  </script>
</body>
</html>`;

    const result = await analyze(html, 'test.html', 'html');

    expect(result.meta.language).toBe('html');
    expect(result.meta.file).toBe('test.html');
  });

  it('should produce attribute-level findings', async () => {
    const html = `<!DOCTYPE html>
<html>
<body>
  <a href="javascript:alert(1)">XSS</a>
  <iframe src="https://example.com"></iframe>
  <a href="https://example.com" target="_blank">No noopener</a>
</body>
</html>`;

    const result = await analyze(html, 'test.html', 'html');

    const findings = result.findings ?? [];
    const ruleIds = findings.map(f => f.rule_id);

    expect(ruleIds).toContain('html-javascript-uri');
    expect(ruleIds).toContain('html-missing-sandbox');
    expect(ruleIds).toContain('html-missing-noopener');
  });

  it('should analyze inline event handlers', async () => {
    const html = `<!DOCTYPE html>
<html>
<body>
  <button onclick="alert('hello')">Click</button>
</body>
</html>`;

    const result = await analyze(html, 'test.html', 'html');

    // Should have at least the inline event handler finding
    const findings = result.findings ?? [];
    const inlineHandler = findings.filter(f => f.rule_id === 'html-inline-event-handler');
    expect(inlineHandler.length).toBeGreaterThanOrEqual(1);
  });

  it('should return valid CircleIR structure for HTML-only pages', async () => {
    const html = `<!DOCTYPE html>
<html>
<body>
  <h1>Hello World</h1>
  <p>No scripts here.</p>
</body>
</html>`;

    const result = await analyze(html, 'test.html', 'html');

    // Should have valid structure even with no scripts
    expect(result.meta.circle_ir).toBe('3.0');
    expect(result.meta.language).toBe('html');
    expect(result.types).toEqual([]);
    expect(result.calls).toEqual([]);
    expect(result.cfg.blocks).toEqual([]);
    expect(result.dfg.defs).toEqual([]);
    expect(result.taint.sources).toEqual([]);
  });

  it('should handle multiple script blocks with correct line offsets', async () => {
    const html = `<!DOCTYPE html>
<html>
<body>
  <script>
    var a = 1;
  </script>
  <p>Between scripts</p>
  <script>
    var b = 2;
  </script>
</body>
</html>`;

    const result = await analyze(html, 'test.html', 'html');

    // Both script blocks should be analyzed
    // DFG should contain defs from both blocks
    expect(result.dfg.defs.length).toBeGreaterThanOrEqual(2);
  });

  it('should detect mixed content and missing SRI', async () => {
    const html = `<!DOCTYPE html>
<html>
<head>
  <script src="http://cdn.example.com/lib.js"></script>
  <link rel="stylesheet" href="https://cdn.example.com/style.css">
</head>
<body></body>
</html>`;

    const result = await analyze(html, 'test.html', 'html');

    const findings = result.findings ?? [];
    expect(findings.some(f => f.rule_id === 'html-mixed-content')).toBe(true);
    expect(findings.some(f => f.rule_id === 'html-missing-sri')).toBe(true);
  });

  it('should report correct file paths in findings', async () => {
    const html = `<!DOCTYPE html>
<html>
<body>
  <a href="javascript:void(0)">Link</a>
  <script>
    eval("dangerous");
  </script>
</body>
</html>`;

    const result = await analyze(html, 'index.html', 'html');

    const findings = result.findings ?? [];
    // All findings should reference the HTML file, not synthetic paths
    for (const finding of findings) {
      expect(finding.file).toBe('index.html');
    }
  });
});
