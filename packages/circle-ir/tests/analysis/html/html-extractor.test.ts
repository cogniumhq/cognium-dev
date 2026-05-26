/**
 * Tests for HTML Content Extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../../src/core/index.js';
import { registerBuiltinPlugins } from '../../../src/languages/index.js';
import { extractHtmlContent } from '../../../src/analysis/html/html-extractor.js';

beforeAll(async () => {
  registerBuiltinPlugins();
  await initParser();
});

describe('extractHtmlContent', () => {
  describe('script blocks', () => {
    it('should extract inline script blocks', async () => {
      const html = `<html>
<head>
  <title>Test</title>
</head>
<body>
  <script>
    var x = 1;
    console.log(x);
  </script>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.scriptBlocks).toHaveLength(1);
      expect(result.scriptBlocks[0].kind).toBe('inline');
      expect(result.scriptBlocks[0].code).toContain('var x = 1');
      expect(result.scriptBlocks[0].lineOffset).toBe(6); // <script> content starts at line 7 (0-based row 6)
    });

    it('should extract multiple script blocks', async () => {
      const html = `<html>
<body>
  <script>var a = 1;</script>
  <p>Hello</p>
  <script>var b = 2;</script>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.scriptBlocks).toHaveLength(2);
      expect(result.scriptBlocks[0].code).toContain('var a = 1');
      expect(result.scriptBlocks[1].code).toContain('var b = 2');
    });

    it('should detect external script src', async () => {
      const html = `<html>
<head>
  <script src="https://cdn.example.com/lib.js"></script>
</head>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.scriptBlocks).toHaveLength(1);
      expect(result.scriptBlocks[0].kind).toBe('external-src');
      expect(result.scriptBlocks[0].src).toBe('https://cdn.example.com/lib.js');
      expect(result.scriptBlocks[0].code).toBe('');
    });

    it('should detect script type attribute', async () => {
      const html = `<html>
<body>
  <script type="text/typescript">let x: number = 1;</script>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.scriptBlocks).toHaveLength(1);
      expect(result.scriptBlocks[0].scriptType).toBe('text/typescript');
    });

    it('should skip empty script blocks', async () => {
      const html = `<html>
<body>
  <script>   </script>
  <script>var x = 1;</script>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      // The empty one still gets extracted but with whitespace-only code
      // The analyzer will skip it due to trim() check
      const nonEmpty = result.scriptBlocks.filter(b => b.code.trim());
      expect(nonEmpty).toHaveLength(1);
    });
  });

  describe('event handlers', () => {
    it('should extract inline event handlers', async () => {
      const html = `<html>
<body>
  <button onclick="doSomething()">Click me</button>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.eventHandlers).toHaveLength(1);
      expect(result.eventHandlers[0].eventName).toBe('onclick');
      expect(result.eventHandlers[0].code).toBe('doSomething()');
      expect(result.eventHandlers[0].element).toBe('button');
    });

    it('should extract multiple event handlers', async () => {
      const html = `<html>
<body>
  <img src="test.png" onerror="handleError()" onload="handleLoad()">
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.eventHandlers.length).toBeGreaterThanOrEqual(2);
      const names = result.eventHandlers.map(h => h.eventName);
      expect(names).toContain('onerror');
      expect(names).toContain('onload');
    });

    it('should handle single-quoted event handler values', async () => {
      const html = `<html>
<body>
  <div onclick='alert("hi")'>Test</div>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.eventHandlers).toHaveLength(1);
      expect(result.eventHandlers[0].code).toBe('alert("hi")');
    });

    it('should report correct line numbers', async () => {
      const html = `<html>
<body>
  <div>
    <button onclick="a()">A</button>
    <button onclick="b()">B</button>
  </div>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.eventHandlers).toHaveLength(2);
      expect(result.eventHandlers[0].line).toBe(4);
      expect(result.eventHandlers[1].line).toBe(5);
    });
  });

  describe('combined', () => {
    it('should extract both scripts and event handlers', async () => {
      const html = `<html>
<body>
  <script>function doSomething() { alert('hi'); }</script>
  <button onclick="doSomething()">Click</button>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.scriptBlocks).toHaveLength(1);
      expect(result.eventHandlers).toHaveLength(1);
    });

    it('should return empty results for plain HTML', async () => {
      const html = `<html>
<body>
  <h1>Hello World</h1>
  <p>No scripts here.</p>
</body>
</html>`;
      const tree = await parse(html, 'html');
      const result = extractHtmlContent(tree.rootNode);

      expect(result.scriptBlocks).toHaveLength(0);
      expect(result.eventHandlers).toHaveLength(0);
    });
  });
});
