/**
 * Tests for HTML Attribute Security Pass
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../../src/core/index.js';
import { registerBuiltinPlugins } from '../../../src/languages/index.js';
import { runHtmlAttributeSecurityChecks } from '../../../src/analysis/html/html-attribute-security-pass.js';

beforeAll(async () => {
  registerBuiltinPlugins();
  await initParser();
});

describe('runHtmlAttributeSecurityChecks', () => {
  // H1: Missing noopener
  describe('html-missing-noopener', () => {
    it('should flag <a target="_blank"> without rel="noopener"', async () => {
      const html = '<html><body><a href="https://example.com" target="_blank">Link</a></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const noopener = findings.filter(f => f.rule_id === 'html-missing-noopener');
      expect(noopener).toHaveLength(1);
      expect(noopener[0].cwe).toBe('CWE-1022');
    });

    it('should not flag when rel="noopener" is present', async () => {
      const html = '<html><body><a href="https://example.com" target="_blank" rel="noopener">Link</a></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-missing-noopener')).toHaveLength(0);
    });

    it('should not flag when rel="noreferrer" is present', async () => {
      const html = '<html><body><a href="https://example.com" target="_blank" rel="noreferrer">Link</a></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-missing-noopener')).toHaveLength(0);
    });

    it('should not flag links without target="_blank"', async () => {
      const html = '<html><body><a href="https://example.com">Link</a></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-missing-noopener')).toHaveLength(0);
    });
  });

  // H2: javascript: URI
  describe('html-javascript-uri', () => {
    it('should flag javascript: in href', async () => {
      const html = '<html><body><a href="javascript:alert(1)">Click</a></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const jsUri = findings.filter(f => f.rule_id === 'html-javascript-uri');
      expect(jsUri).toHaveLength(1);
      expect(jsUri[0].cwe).toBe('CWE-79');
      expect(jsUri[0].level).toBe('error');
    });

    it('should flag javascript: in src', async () => {
      const html = '<html><body><iframe src="javascript:void(0)"></iframe></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const jsUri = findings.filter(f => f.rule_id === 'html-javascript-uri');
      expect(jsUri.length).toBeGreaterThanOrEqual(1);
    });

    it('should not flag normal URLs', async () => {
      const html = '<html><body><a href="https://example.com">Link</a></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-javascript-uri')).toHaveLength(0);
    });
  });

  // H3: Missing sandbox
  describe('html-missing-sandbox', () => {
    it('should flag <iframe> without sandbox', async () => {
      const html = '<html><body><iframe src="https://example.com"></iframe></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const sandbox = findings.filter(f => f.rule_id === 'html-missing-sandbox');
      expect(sandbox).toHaveLength(1);
      expect(sandbox[0].cwe).toBe('CWE-1021');
    });

    it('should not flag <iframe> with sandbox', async () => {
      const html = '<html><body><iframe src="https://example.com" sandbox="allow-scripts"></iframe></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-missing-sandbox')).toHaveLength(0);
    });

    it('should accept empty sandbox attribute', async () => {
      const html = '<html><body><iframe src="https://example.com" sandbox></iframe></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-missing-sandbox')).toHaveLength(0);
    });
  });

  // H4: Mixed content
  describe('html-mixed-content', () => {
    it('should flag http:// script src', async () => {
      const html = '<html><body><script src="http://cdn.example.com/lib.js"></script></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const mixed = findings.filter(f => f.rule_id === 'html-mixed-content');
      expect(mixed).toHaveLength(1);
      expect(mixed[0].cwe).toBe('CWE-319');
    });

    it('should flag http:// img src', async () => {
      const html = '<html><body><img src="http://example.com/img.png"></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const mixed = findings.filter(f => f.rule_id === 'html-mixed-content');
      expect(mixed).toHaveLength(1);
    });

    it('should not flag https:// resources', async () => {
      const html = '<html><body><script src="https://cdn.example.com/lib.js"></script></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-mixed-content')).toHaveLength(0);
    });
  });

  // H5: Missing SRI
  describe('html-missing-sri', () => {
    it('should flag external script without integrity', async () => {
      const html = '<html><head><script src="https://cdn.example.com/lib.js"></script></head></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const sri = findings.filter(f => f.rule_id === 'html-missing-sri');
      expect(sri).toHaveLength(1);
      expect(sri[0].cwe).toBe('CWE-353');
    });

    it('should not flag script with integrity', async () => {
      const html = '<html><head><script src="https://cdn.example.com/lib.js" integrity="sha384-abc123"></script></head></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-missing-sri')).toHaveLength(0);
    });

    it('should flag external stylesheet without integrity', async () => {
      const html = '<html><head><link rel="stylesheet" href="https://cdn.example.com/style.css"></head></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const sri = findings.filter(f => f.rule_id === 'html-missing-sri');
      expect(sri).toHaveLength(1);
    });

    it('should not flag local scripts', async () => {
      const html = '<html><head><script src="/js/app.js"></script></head></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-missing-sri')).toHaveLength(0);
    });
  });

  // H6: Autocomplete on sensitive inputs
  describe('html-autocomplete-sensitive', () => {
    it('should flag password input without autocomplete="off"', async () => {
      const html = '<html><body><form><input type="password" name="pass"></form></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const auto = findings.filter(f => f.rule_id === 'html-autocomplete-sensitive');
      expect(auto).toHaveLength(1);
      expect(auto[0].cwe).toBe('CWE-525');
    });

    it('should not flag password with autocomplete="off"', async () => {
      const html = '<html><body><form><input type="password" autocomplete="off"></form></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-autocomplete-sensitive')).toHaveLength(0);
    });

    it('should not flag password with autocomplete="new-password"', async () => {
      const html = '<html><body><form><input type="password" autocomplete="new-password"></form></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-autocomplete-sensitive')).toHaveLength(0);
    });

    it('should not flag non-sensitive inputs', async () => {
      const html = '<html><body><form><input type="text" name="username"></form></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-autocomplete-sensitive')).toHaveLength(0);
    });
  });

  // H7: Inline event handlers
  describe('html-inline-event-handler', () => {
    it('should flag inline onclick', async () => {
      const html = '<html><body><button onclick="alert(1)">Click</button></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const inline = findings.filter(f => f.rule_id === 'html-inline-event-handler');
      expect(inline).toHaveLength(1);
      expect(inline[0].level).toBe('note');
    });

    it('should flag multiple handlers on same element', async () => {
      const html = '<html><body><img src="x" onerror="handleErr()" onload="handleLoad()"></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const inline = findings.filter(f => f.rule_id === 'html-inline-event-handler');
      expect(inline).toHaveLength(2);
    });
  });

  // H8: Form action javascript:
  describe('html-form-action-javascript', () => {
    it('should flag form action="javascript:..."', async () => {
      const html = '<html><body><form action="javascript:submit()"><button>Go</button></form></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      const formJs = findings.filter(f => f.rule_id === 'html-form-action-javascript');
      expect(formJs).toHaveLength(1);
      expect(formJs[0].cwe).toBe('CWE-79');
      expect(formJs[0].level).toBe('error');
    });

    it('should not flag normal form actions', async () => {
      const html = '<html><body><form action="/submit"><button>Go</button></form></body></html>';
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings.filter(f => f.rule_id === 'html-form-action-javascript')).toHaveLength(0);
    });
  });

  // Combined
  describe('combined scenarios', () => {
    it('should detect multiple issues in a single HTML file', async () => {
      const html = `<html>
<head>
  <script src="http://cdn.example.com/lib.js"></script>
  <link rel="stylesheet" href="https://cdn.example.com/style.css">
</head>
<body>
  <a href="javascript:void(0)" target="_blank">Link</a>
  <iframe src="https://example.com"></iframe>
  <form action="javascript:submit()">
    <input type="password" name="pass">
    <button onclick="doSubmit()">Go</button>
  </form>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      // Should have multiple types of findings
      const ruleIds = new Set(findings.map(f => f.rule_id));
      expect(ruleIds.has('html-mixed-content')).toBe(true);
      expect(ruleIds.has('html-missing-sri')).toBe(true);
      expect(ruleIds.has('html-javascript-uri')).toBe(true);
      expect(ruleIds.has('html-missing-noopener')).toBe(true);
      expect(ruleIds.has('html-missing-sandbox')).toBe(true);
      expect(ruleIds.has('html-form-action-javascript')).toBe(true);
      expect(ruleIds.has('html-autocomplete-sensitive')).toBe(true);
      expect(ruleIds.has('html-inline-event-handler')).toBe(true);
    });

    it('should return no findings for clean HTML', async () => {
      const html = `<html>
<head>
  <script src="https://cdn.example.com/lib.js" integrity="sha384-abc123"></script>
  <link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha384-def456">
</head>
<body>
  <a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>
  <iframe src="https://example.com" sandbox="allow-scripts"></iframe>
  <form action="/submit">
    <input type="password" autocomplete="new-password">
    <button type="submit">Go</button>
  </form>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const findings = runHtmlAttributeSecurityChecks(tree.rootNode, 'test.html');

      expect(findings).toHaveLength(0);
    });
  });
});
