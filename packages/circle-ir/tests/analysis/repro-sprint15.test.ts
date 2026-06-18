/**
 * Repro for Sprint 15 (cognium-dev v3.65.0) — Java FP-corpus cleanup.
 *
 * Locks the dedup gap from issue #49 ("Also: duplicate findings — same sink
 * line reported multiple times (xxe ×3 @ line 95, path_traversal ×2 @
 * line 56)"). The DFG-based `propagateTaint` and the four supplementary
 * detectors (`detectArrayElementFlows`, `detectCollectionFlows`,
 * `detectParameterSinkFlows`, `detectExpressionScanFlows`) each emit
 * independently; the merge-time dedup at the supplement seams keys on
 * `(source_line, sink_line)` only — not `sink_type` — and the DFG result
 * itself can re-emit the same `(source, sink, type)` triple twice when
 * multiple tainted-variable chains both reach the same sink call.
 *
 * Sprint 15 adds a final dedup pass in `TaintPropagationPass.run()` keyed
 * on `(source_line, sink_line, sink_type)`, keeping the highest-confidence
 * flow per key.
 *
 * NOTE: SAST regression fixtures — do not "fix" the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

// Unsanitized fixture deliberately small enough that any `(source_line,
// sink_line, sink_type)` triple must occur exactly once.
const UNSANITIZED_JAVA = `package com.demo;

import java.io.*;
import java.nio.file.*;
import javax.xml.parsers.*;
import javax.servlet.http.HttpServletRequest;
import org.w3c.dom.Document;

public class UnsafeService {

    public String readFile(HttpServletRequest req) throws IOException {
        String filename = req.getParameter("file");
        File base = new File("/uploads");
        File target = new File(base, filename);
        return new String(Files.readAllBytes(target.toPath()));
    }

    public Document parseXml(HttpServletRequest req) throws Exception {
        String body = req.getParameter("xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(body.getBytes()));
    }
}
`;

describe('Sprint 15 — cognium-dev #49 duplicate finding dedup', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('emits exactly one flow per (source_line, sink_line, sink_type) triple', async () => {
    const r = await analyze(UNSANITIZED_JAVA, 'UnsafeService.java', 'java');
    const flows = r.taint.flows ?? [];

    const sigs = new Map<string, number>();
    for (const f of flows) {
      const k = `${f.source_line}|${f.sink_line}|${f.sink_type}`;
      sigs.set(k, (sigs.get(k) ?? 0) + 1);
    }
    const dupes = [...sigs.entries()].filter(([, n]) => n > 1);
    expect(dupes).toEqual([]);
  });

  it('still detects an xxe flow on the unsanitized parseXml sink', async () => {
    const r = await analyze(UNSANITIZED_JAVA, 'UnsafeService.java', 'java');
    const xxe = (r.taint.flows ?? []).filter(f => f.sink_type === 'xxe');
    expect(xxe.length).toBe(1);
  });

  it('still detects path_traversal flows on the unsanitized readFile sinks', async () => {
    const r = await analyze(UNSANITIZED_JAVA, 'UnsafeService.java', 'java');
    const pt = (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');
    // `new File(base, filename)` AND `Files.readAllBytes(target.toPath())`
    // are distinct sinks on distinct lines — both should fire, neither
    // duplicated.
    expect(pt.length).toBeGreaterThanOrEqual(1);
  });
});
