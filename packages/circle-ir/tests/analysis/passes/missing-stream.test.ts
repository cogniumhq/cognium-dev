/**
 * Tests for Pass #85: missing-stream (category: performance)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { MissingStreamPass } from '../../../src/analysis/passes/missing-stream-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 20, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {},
    ...overrides,
  };
}

function makeCtx(ir: CircleIR, code: string): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code,
    language: ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

describe('MissingStreamPass', () => {
  it('flags readFileSync in a method body with no streaming (TypeScript)', () => {
    const ir = makeIR({
      types: [{
        name: 'FileLoader',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'loadAll',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 5,
        }],
        fields: [],
        start_line: 1,
        end_line: 6,
      }],
    });
    const code = `class FileLoader {
  loadAll() {
    const data = readFileSync('huge.json', 'utf8');
    return JSON.parse(data);
  }
}`;
    const ctx = makeCtx(ir, code);
    const result = new MissingStreamPass().run(ctx);
    expect(result.wholeFileReads.length).toBeGreaterThanOrEqual(1);
    expect(result.wholeFileReads[0].method).toMatch(/readFileSync/);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].level).toBe('note');
    expect(ctx.findings[0].severity).toBe('low');
    expect(ctx.findings[0].message).toMatch(/readFileSync/);
  });

  it('does NOT flag readFileSync in a method that also uses createReadStream', () => {
    const ir = makeIR({
      types: [{
        name: 'FileLoader',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'streamLoad',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 8,
        }],
        fields: [],
        start_line: 1,
        end_line: 10,
      }],
    });
    const code = `class FileLoader {
  streamLoad() {
    // use createReadStream for large files
    const stream = createReadStream('large.csv');
    const data = readFileSync('small.json');
    return data;
  }
}`;
    const ctx = makeCtx(ir, code);
    const result = new MissingStreamPass().run(ctx);
    expect(result.wholeFileReads).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT flag response.text() in a method that uses pipe', () => {
    const ir = makeIR({
      types: [{
        name: 'Fetcher',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'download',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 7,
        }],
        fields: [],
        start_line: 1,
        end_line: 9,
      }],
    });
    const code = `class Fetcher {
  download() {
    const res = fetch(url);
    res.body.pipe(fileStream);
    const txt = response.text();
  }
}`;
    const ctx = makeCtx(ir, code);
    const result = new MissingStreamPass().run(ctx);
    expect(result.wholeFileReads).toHaveLength(0);
  });

  it('flags Files.readAllBytes in Java', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'FileUtil.java', language: 'java', loc: 10, hash: '' },
    });
    const code = `public class FileUtil {
  public byte[] load(Path p) throws IOException {
    byte[] data = Files.readAllBytes(p);
    return data;
  }
}`;
    const ctx = makeCtx(ir, code);
    const result = new MissingStreamPass().run(ctx);
    expect(result.wholeFileReads.length).toBeGreaterThanOrEqual(1);
    expect(result.wholeFileReads[0].method).toMatch(/Files\.readAllBytes/);
    expect(ctx.findings[0].level).toBe('note');
  });

  it('flags .read() in Python', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'loader.py', language: 'python', loc: 8, hash: '' },
    });
    const code = `def load_data(path):
    with open(path) as f:
        data = f.read()
    return data`;
    const ctx = makeCtx(ir, code);
    const result = new MissingStreamPass().run(ctx);
    expect(result.wholeFileReads.some(r => r.method === 'read')).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'missing-stream')).toBe(true);
  });

  it('is a no-op for Bash', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'script.sh', language: 'bash', loc: 5, hash: '' },
    });
    const ctx = makeCtx(ir, 'data=$(cat file.txt)\necho "$data"');
    const result = new MissingStreamPass().run(ctx);
    expect(result.wholeFileReads).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('includes correct metadata in findings', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'src/util/io.ts', language: 'typescript', loc: 10, hash: '' },
      types: [{
        name: 'IOUtil',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'readConfig',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: [],
          start_line: 1,
          end_line: 6,
        }],
        fields: [],
        start_line: 1,
        end_line: 8,
      }],
    });
    const code = `class IOUtil {
  readConfig() {
    const buf = fs.readFileSync('./config.json');
    return JSON.parse(buf);
  }
}`;
    const ctx = makeCtx(ir, code);
    new MissingStreamPass().run(ctx);
    expect(ctx.findings[0].file).toBe('src/util/io.ts');
    expect(ctx.findings[0].pass).toBe('missing-stream');
    expect(ctx.findings[0].category).toBe('performance');
  });
});
