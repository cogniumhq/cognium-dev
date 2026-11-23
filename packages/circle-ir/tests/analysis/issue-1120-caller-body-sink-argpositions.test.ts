/**
 * cognium-dev #1120 — caller-body sinks must honor sink argPositions and the sink call only.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #1120 — caller-body sink argPositions', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const requestWrapper = `package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class RequestWrapper {
    private final HttpServletRequest request;

    public RequestWrapper(HttpServletRequest request) {
        this.request = request;
    }

    public String fetchField(String name) {
        return request.getParameter(name);
    }
}
`;

  const writerServlet = `import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.acme.web.RequestWrapper;

public class WriterServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        RequestWrapper wrap = new RequestWrapper(request);
        String body = wrap.fetchField("invoice");
        Files.write(Paths.get("/tmp/fixed.json"), body.getBytes(StandardCharsets.UTF_8));
        String outPath = wrap.fetchField("out");
        Files.write(Paths.get(outPath), "ok".getBytes(StandardCharsets.UTF_8));
    }
}
`;

  it('does not emit path_traversal when tainted bytes are Files.write arg 1 only', async () => {
    const r = await analyzeProject([
      { filePath: 'com/acme/web/RequestWrapper.java', code: requestWrapper, language: 'java' },
      { filePath: 'WriterServlet.java', code: writerServlet, language: 'java' },
    ]);
    const paths = (r.taint_paths ?? []).filter(
      (p) => !p.sanitized && p.sink?.type === 'path_traversal' && p.sink.file === 'WriterServlet.java',
    );
    const fixedLine =
      writerServlet.split('\n').findIndex((l) => l.includes('Paths.get("/tmp/fixed.json")')) + 1;
    const dynamicLine =
      writerServlet.split('\n').findIndex((l) => l.includes('Paths.get(outPath)')) + 1;
    expect(paths.some((p) => p.sink.line === fixedLine)).toBe(false);
    expect(paths.some((p) => p.sink.line === dynamicLine)).toBe(true);
  });

  it('does not credit a sibling call arg on the same line as readFileSync', async () => {
    const helper = `export function loadBody(url: string): string {
  return url + '-payload';
}`;
    const code = `import * as fs from 'fs';
import express from 'express';
import { loadBody } from './helper.js';

const app = express();
function diffEnvironment(a: string, b: string): void {
  console.log(a.length, b.length);
}

app.get('/run', (req, res) => {
  const learned = loadBody(String(req.query.url));
  diffEnvironment(fs.readFileSync('/etc/config', 'utf-8'), learned);
});
`;
    const r = await analyzeProject([
      { filePath: 'helper.ts', language: 'typescript', code: helper },
      { filePath: 'runner.ts', language: 'typescript', code },
    ]);
    const paths = (r.taint_paths ?? []).filter(
      (p) => !p.sanitized && p.sink?.type === 'path_traversal',
    );
    expect(paths).toHaveLength(0);
  });
});
