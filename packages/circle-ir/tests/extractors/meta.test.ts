/**
 * Tests for Meta extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse, isInitialized, isLanguageLoaded } from '../../src/core/parser.js';
import { extractMeta } from '../../src/core/extractors/meta.js';

describe('Meta Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract basic metadata', async () => {
    const code = `
package com.example;

public class Test {
    public void method() {}
}
`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/Test.java', 'java');

    expect(meta.circle_ir).toBe('3.0');
    expect(meta.file).toBe('/path/to/Test.java');
    expect(meta.language).toBe('java');
    expect(meta.loc).toBeGreaterThan(0);
    expect(meta.hash).toHaveLength(16);
    expect(meta.package).toBe('com.example');
  });

  it('should handle files without package declaration', async () => {
    const code = `
public class Test {
    public void method() {}
}
`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/Test.java', 'java');

    expect(meta.package).toBeUndefined();
  });

  it('should count lines of code correctly', async () => {
    const code = `
// This is a comment
package com.example;

/*
 * Block comment
 */
public class Test {
    // Another comment
    public void method() {
        int x = 1;
    }
}
`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/Test.java', 'java');

    // Should count: package, class declaration, method signature, int x = 1, closing braces
    expect(meta.loc).toBeGreaterThanOrEqual(4);
    expect(meta.loc).toBeLessThanOrEqual(8);
  });

  it('should generate consistent hash for same code', async () => {
    const code = `public class Test {}`;
    const tree1 = await parse(code, 'java');
    const tree2 = await parse(code, 'java');

    const meta1 = extractMeta(code, tree1, '/path/to/Test.java', 'java');
    const meta2 = extractMeta(code, tree2, '/path/to/Test.java', 'java');

    expect(meta1.hash).toBe(meta2.hash);
  });

  it('should generate different hash for different code', async () => {
    const code1 = `public class Test1 {}`;
    const code2 = `public class Test2 {}`;

    const tree1 = await parse(code1, 'java');
    const tree2 = await parse(code2, 'java');

    const meta1 = extractMeta(code1, tree1, '/path/to/Test.java', 'java');
    const meta2 = extractMeta(code2, tree2, '/path/to/Test.java', 'java');

    expect(meta1.hash).not.toBe(meta2.hash);
  });

  it('should handle inline block comments', async () => {
    // Inline block comment on a single line - the algorithm skips lines starting with /*
    const code = `/* comment */
public class Test {}`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/Test.java', 'java');

    // Should count the class declaration line
    expect(meta.loc).toBe(1);
  });

  it('should handle code after end of block comment', async () => {
    const code = `/*
     * Multi-line comment
     */ public class Test {
    public void method() {}
}`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/Test.java', 'java');

    // Should count lines after the block comment ends
    expect(meta.loc).toBeGreaterThanOrEqual(2);
  });

  it('should handle nested package names', async () => {
    const code = `
package org.springframework.web.bind.annotation;

public class Controller {}
`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/Controller.java', 'java');

    expect(meta.package).toBe('org.springframework.web.bind.annotation');
  });

  it('should handle simple single-segment package', async () => {
    const code = `
package myapp;

public class App {}
`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/App.java', 'java');

    expect(meta.package).toBe('myapp');
  });

  it('should skip asterisk lines in block comments', async () => {
    const code = `/**
 * Javadoc comment
 * @author Test
 */
public class Test {}`;
    const tree = await parse(code, 'java');
    const meta = extractMeta(code, tree, '/path/to/Test.java', 'java');

    // Should only count the class declaration, not the javadoc lines
    expect(meta.loc).toBe(1);
  });

  it('should report parser initialization status', () => {
    // After beforeAll, parser should be initialized
    expect(isInitialized()).toBe(true);
    // Java should be loaded since we used it in tests
    expect(isLanguageLoaded('java')).toBe(true);
  });
});
