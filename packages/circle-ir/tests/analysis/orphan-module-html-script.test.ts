/**
 * orphan-module through analyzeProject: a script an HTML page loads with
 * <script src> is in use, and minified files are build output.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const page = `<!DOCTYPE html>
<html>
<head>
<link href="content/css/site.css" rel="stylesheet">
<script src="content/js/ie-warning.js" type="text/javascript"></script>
</head>
<body>
<h1>Report</h1>
<script src="https://cdn.example.com/jquery.min.js"></script>
<script src="content/js/charts.js"></script>
<!-- <script src="content/js/stale.js"></script> -->
</body>
</html>
`;

function orphanFiles(result: Awaited<ReturnType<typeof analyzeProject>>): string[] {
  return result.files
    .flatMap(f => f.analysis.findings ?? [])
    .filter(f => f.rule_id === 'orphan-module')
    .map(f => f.file)
    .sort();
}

describe('orphan-module: HTML-loaded and minified scripts', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('counts <script src> as use, skips .min.js, still flags an unloaded script', async () => {
    const result = await analyzeProject([
      { filePath: 'report/template.html', language: 'html', code: page },
      { filePath: 'report/content/js/charts.js', language: 'javascript', code: 'export function draw(el) { el.textContent = "chart"; }\n' },
      { filePath: 'report/content/js/vendor.min.js', language: 'javascript', code: 'var a=1;\n' },
      { filePath: 'report/content/js/stale.js', language: 'javascript', code: 'export function old() { return 1; }\n' },
    ]);
    expect(orphanFiles(result)).toEqual(['report/content/js/stale.js']);
  });

  it('counts a Vue single-file component <script src> as use', async () => {
    const sfc = `<template><div>{{ msg }}</div></template>\n<script src="./hello-logic.js"></script>\n`;
    const result = await analyzeProject([
      { filePath: 'web/Hello.vue', language: 'vue', code: sfc },
      { filePath: 'web/hello-logic.js', language: 'javascript', code: 'export default { data() { return { msg: "hi" }; } };\n' },
    ]);
    expect(orphanFiles(result)).not.toContain('web/hello-logic.js');
  });
});
