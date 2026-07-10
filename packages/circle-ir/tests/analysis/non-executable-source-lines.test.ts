/**
 * cognium-dev#250 — Non-executable source-line gate.
 *
 * Locks in the defense-in-depth filter that drops fabricated taint
 * sources whose `line` points at an import/package/comment/annotation/
 * const-literal declaration. These lines cannot legitimately host a
 * runtime taint source; when they show up in `sources[]` they are
 * always either LLM enrichment hallucinations or detector regressions.
 */

import { describe, it, expect } from 'vitest';
import {
  isNonExecutableSourceLine,
} from '../../src/analysis/non-executable-lines.js';
import { generateFindings } from '../../src/analysis/findings.js';
import type { TaintSource, TaintSink, DFG } from '../../src/types/index.js';

const EMPTY_DFG: DFG = { defs: [], uses: [], chains: [] };

describe('isNonExecutableSourceLine — Java', () => {
  const code = [
    '/*',                                                 // 1
    ' * Copyright 2018 OpenAPI-Generator Contributors',   // 2
    ' *',                                                 // 3
    ' * Licensed under the Apache License, Version 2.0',  // 4
    ' */',                                                // 5
    '',                                                   // 6
    'package org.openapitools.codegen.config;',           // 7
    '',                                                   // 8
    'import java.util.List;',                             // 9
    'import java.util.Map;',                              // 10
    '',                                                   // 11
    '@Deprecated',                                        // 12
    'public class CodegenConfigurator {',                 // 13
    '    private static final String CONST = "abc";',    // 14
    '    private String field;',                          // 15
    '    public void handle(String x) {',                 // 16
    '        this.field = x;',                            // 17
    '        LOGGER.info(x);',                            // 18
    '    }',                                              // 19
    '}',                                                  // 20
  ].join('\n');

  it('flags block-comment opener', () => {
    expect(isNonExecutableSourceLine(code, 1, 'java')).toBe(true);
  });
  it('flags block-comment interior star lines', () => {
    expect(isNonExecutableSourceLine(code, 2, 'java')).toBe(true);
    expect(isNonExecutableSourceLine(code, 3, 'java')).toBe(true);
  });
  it('flags block-comment closer', () => {
    expect(isNonExecutableSourceLine(code, 5, 'java')).toBe(true);
  });
  it('flags blank lines', () => {
    expect(isNonExecutableSourceLine(code, 6, 'java')).toBe(true);
  });
  it('flags package declaration', () => {
    expect(isNonExecutableSourceLine(code, 7, 'java')).toBe(true);
  });
  it('flags import declarations', () => {
    expect(isNonExecutableSourceLine(code, 9, 'java')).toBe(true);
    expect(isNonExecutableSourceLine(code, 10, 'java')).toBe(true);
  });
  it('flags standalone annotation lines', () => {
    expect(isNonExecutableSourceLine(code, 12, 'java')).toBe(true);
  });
  it('flags final-static-literal constant declarations', () => {
    expect(isNonExecutableSourceLine(code, 14, 'java')).toBe(true);
  });
  it('does NOT flag class declaration', () => {
    expect(isNonExecutableSourceLine(code, 13, 'java')).toBe(false);
  });
  it('does NOT flag field declaration without literal init', () => {
    expect(isNonExecutableSourceLine(code, 15, 'java')).toBe(false);
  });
  it('does NOT flag method signature', () => {
    expect(isNonExecutableSourceLine(code, 16, 'java')).toBe(false);
  });
  it('does NOT flag real assignments or logger calls', () => {
    expect(isNonExecutableSourceLine(code, 17, 'java')).toBe(false);
    expect(isNonExecutableSourceLine(code, 18, 'java')).toBe(false);
  });
});

describe('isNonExecutableSourceLine — Python', () => {
  const code = [
    '# Copyright header',                    // 1
    '"""module docstring',                   // 2
    'multi line',                            // 3
    '"""',                                   // 4
    '',                                      // 5
    'import os',                             // 6
    'from typing import Any',                // 7
    '',                                      // 8
    'API_URL = "https://api.example.com"',   // 9
    '',                                      // 10
    '@app.route("/x")',                      // 11
    'def handle(request):',                  // 12
    '    val = request.args.get("q")',       // 13
    '    return val',                        // 14
  ].join('\n');

  it('flags hash comments', () => {
    expect(isNonExecutableSourceLine(code, 1, 'python')).toBe(true);
  });
  it('flags docstring delimiters', () => {
    expect(isNonExecutableSourceLine(code, 4, 'python')).toBe(true);
  });
  it('flags import + from', () => {
    expect(isNonExecutableSourceLine(code, 6, 'python')).toBe(true);
    expect(isNonExecutableSourceLine(code, 7, 'python')).toBe(true);
  });
  it('flags module-level UPPER_SNAKE literal constants', () => {
    expect(isNonExecutableSourceLine(code, 9, 'python')).toBe(true);
  });
  it('flags decorators on their own line', () => {
    expect(isNonExecutableSourceLine(code, 11, 'python')).toBe(true);
  });
  it('does NOT flag def signature or executable assignment', () => {
    expect(isNonExecutableSourceLine(code, 12, 'python')).toBe(false);
    expect(isNonExecutableSourceLine(code, 13, 'python')).toBe(false);
  });
});

describe('isNonExecutableSourceLine — JS/TS', () => {
  const code = [
    '// Copyright header',              // 1
    '/**',                              // 2
    ' * jsdoc',                         // 3
    ' */',                              // 4
    "import express from 'express';",   // 5
    "const API = 'x';",                 // 6
    "const app = express();",           // 7
    "app.get('/x', (req, res) => {",    // 8
    '  res.send(req.query.q);',         // 9
    '});',                              // 10
  ].join('\n');

  it('flags // and JSDoc', () => {
    expect(isNonExecutableSourceLine(code, 1, 'javascript')).toBe(true);
    expect(isNonExecutableSourceLine(code, 2, 'typescript')).toBe(true);
    expect(isNonExecutableSourceLine(code, 3, 'javascript')).toBe(true);
    expect(isNonExecutableSourceLine(code, 4, 'javascript')).toBe(true);
  });
  it('flags ESM imports', () => {
    expect(isNonExecutableSourceLine(code, 5, 'javascript')).toBe(true);
  });
  it('flags const-with-string-literal', () => {
    expect(isNonExecutableSourceLine(code, 6, 'javascript')).toBe(true);
  });
  it('does NOT flag const-with-call-expression', () => {
    expect(isNonExecutableSourceLine(code, 7, 'javascript')).toBe(false);
  });
  it('does NOT flag route handler body', () => {
    expect(isNonExecutableSourceLine(code, 8, 'javascript')).toBe(false);
    expect(isNonExecutableSourceLine(code, 9, 'javascript')).toBe(false);
  });
});

describe('isNonExecutableSourceLine — Go / Rust', () => {
  const goCode = [
    'package main',                                        // 1
    '',                                                    // 2
    'import "net/http"',                                   // 3
    'const AppName = "cognium"',                           // 4
    'func Handle(r *http.Request) string {',               // 5
    '  q := r.URL.Query().Get("q")',                       // 6
    '  return q',                                          // 7
    '}',                                                   // 8
  ].join('\n');
  it('flags Go package + import + const', () => {
    expect(isNonExecutableSourceLine(goCode, 1, 'go')).toBe(true);
    expect(isNonExecutableSourceLine(goCode, 3, 'go')).toBe(true);
    expect(isNonExecutableSourceLine(goCode, 4, 'go')).toBe(true);
  });
  it('does NOT flag Go executable body', () => {
    expect(isNonExecutableSourceLine(goCode, 6, 'go')).toBe(false);
  });

  const rustCode = [
    '// SPDX-License-Identifier: MIT',       // 1
    'use std::io;',                          // 2
    'const APP: &str = "cognium";',          // 3
    'fn handle(input: &str) -> String {',    // 4
    '    let x = input.to_string();',        // 5
    '    x',                                 // 6
    '}',                                     // 7
  ].join('\n');
  it('flags Rust use + const', () => {
    expect(isNonExecutableSourceLine(rustCode, 1, 'rust')).toBe(true);
    expect(isNonExecutableSourceLine(rustCode, 2, 'rust')).toBe(true);
    expect(isNonExecutableSourceLine(rustCode, 3, 'rust')).toBe(true);
  });
  it('does NOT flag Rust body', () => {
    expect(isNonExecutableSourceLine(rustCode, 5, 'rust')).toBe(false);
  });
});

describe('isNonExecutableSourceLine — edge cases', () => {
  it('returns false on empty sourceCode', () => {
    expect(isNonExecutableSourceLine('', 1, 'java')).toBe(false);
  });
  it('returns false on out-of-range line', () => {
    expect(isNonExecutableSourceLine('x', 999, 'java')).toBe(false);
    expect(isNonExecutableSourceLine('x', 0, 'java')).toBe(false);
    expect(isNonExecutableSourceLine('x', -1, 'java')).toBe(false);
  });
  it('returns false on unknown language', () => {
    expect(isNonExecutableSourceLine('import x', 1, 'cobol')).toBe(false);
  });
});

describe('generateFindings — drops fabricated import-line sources (cognium-dev#250)', () => {
  // Reproduces the exact shape of the fabricated flow observed in the
  // tier-2 sweep on openapi-generator/CodegenConfigurator.java:
  //   http_param at line 10 (an import) → log_injection sink at line 194
  const code = [
    '/*',                                                 // 1
    ' * Copyright header',                                // 2
    ' */',                                                // 3
    'package org.openapitools.codegen.config;',           // 4
    '',                                                   // 5
    'import java.util.List;',                             // 6
    'import java.util.Map;',                              // 7
    'import java.io.IOException;',                        // 8
    'import java.io.File;',                               // 9
    'import java.util.HashMap;',                          // 10
    '',                                                   // 11
    'public class CodegenConfigurator {',                 // 12
    '    private static final Logger LOGGER = ' +
      'LoggerFactory.getLogger(CodegenConfigurator.class);', // 13
    '    public void handle(String inputSpec) {',         // 14
    '        try {',                                      // 15
    '            doWork(inputSpec);',                     // 16
    '        } catch (IOException ex) {',                 // 17
    '            LOGGER.error(ex.getMessage());',         // 18 sink
    '        }',                                          // 19
    '    }',                                              // 20
  ].join('\n');

  const fabricatedSource: TaintSource = {
    type: 'http_param',
    location: '', // #250 telltale — empty code snippet
    severity: 'high',
    line: 10,     // import java.util.HashMap;
    confidence: 0.8,
  };
  // Use xss — http_param → xss IS in canSourceReachSink's map. The tier-2
  // finding at hand used http_param → log_injection, which reaches
  // cognium-ai's verified path directly (bypassing generateFindings), so
  // that combination cannot be reproduced here. xss exercises the same
  // gate at the generateFindings entry point.
  const realSink: TaintSink = {
    type: 'xss',
    method: 'write',
    location: 'response.getWriter().write(inputSpec);',
    severity: 'high',
    line: 18,
    cwe: 'CWE-79',
  };

  it('emits the fabricated finding when gate is not engaged (legacy caller)', () => {
    const findings = generateFindings(
      [fabricatedSource],
      [realSink],
      EMPTY_DFG,
      'CodegenConfigurator.java',
    );
    // No gate → fabricated flow leaks through when proximity holds
    // (|source.line - sink.line| = 8 ≤ 50).
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].source.line).toBe(10);
  });

  it('drops the fabricated finding when sourceCode+language are supplied', () => {
    const findings = generateFindings(
      [fabricatedSource],
      [realSink],
      EMPTY_DFG,
      'CodegenConfigurator.java',
      code,
      'java',
    );
    expect(findings.length).toBe(0);
  });

  it('does not suppress a real assignment-line source in the same call', () => {
    const realSource: TaintSource = {
      type: 'http_param',
      location: 'doWork(inputSpec);',
      severity: 'high',
      line: 16, // real method body line
      confidence: 0.8,
    };
    const findings = generateFindings(
      [fabricatedSource, realSource],
      [realSink],
      EMPTY_DFG,
      'CodegenConfigurator.java',
      code,
      'java',
    );
    expect(findings.length).toBe(1);
    expect(findings[0].source.line).toBe(16);
  });
});
