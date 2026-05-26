/**
 * Pass #85: missing-stream (category: performance)
 *
 * Detects whole-file / whole-response reads that load the entire payload into
 * memory when a streaming approach would be more memory-efficient.
 *
 * Detection strategy (source-text heuristics):
 *   JS/TS  — fs.readFile / fs.readFileSync / response.text() / response.json()
 *            in a method body that has no adjacent streaming indicator
 *            (.pipe / for-await-of / createReadStream).
 *   Java   — Files.readAllBytes / Files.readAllLines / Files.readString or a
 *            new BufferedReader constructor.
 *   Python — file_handle.read() (whole-file read).
 *
 * Languages: JavaScript, TypeScript, Java, Python. Bash / Rust — skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** JS/TS calls that read an entire file or HTTP response into memory. */
const JS_WHOLE_LOAD_RE =
  /\b(?:readFileSync|fs\.readFile\b|response\.text\b|response\.json\b|res\.text\b|res\.json\b|body\.text\b|body\.json\b)\s*\(/;

/** Indicators that the method already uses streaming in JS/TS. */
const JS_STREAM_RE =
  /\.pipe\s*\(|\.on\s*\(\s*['"]data['"]|for\s+await\s*\(|\bcreateReadStream\b|\bstream\b/i;

/** Java patterns that load an entire file eagerly. */
const JAVA_WHOLE_READ_RE =
  /\bFiles\.readAllBytes\s*\(|\bFiles\.readAllLines\s*\(|\bFiles\.readString\s*\(|\bnew\s+BufferedReader\s*\(|\bFileInputStream\b/;

/** Python: calling .read() with no arguments loads the whole file. */
const PYTHON_WHOLE_READ_RE = /\.\s*read\s*\(\s*\)/;

export interface MissingStreamResult {
  wholeFileReads: Array<{ line: number; method: string }>;
}

export class MissingStreamPass implements AnalysisPass<MissingStreamResult> {
  readonly name = 'missing-stream';
  readonly category = 'performance' as const;

  run(ctx: PassContext): MissingStreamResult {
    const { graph, code, language } = ctx;

    if (language === 'bash' || language === 'rust') {
      return { wholeFileReads: [] };
    }

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const numCodeLines = codeLines.length;
    const wholeFileReads: MissingStreamResult['wholeFileReads'] = [];
    const reported = new Set<number>();

    if (language === 'javascript' || language === 'typescript') {
      // Check per method: only flag if the method body has no streaming indicator
      for (const type of graph.ir.types) {
        for (const method of type.methods) {
          const start = method.start_line;
          const end = method.end_line;
          const methodSrc = codeLines.slice(start - 1, end).join('\n');

          // Skip methods that already use streaming
          if (JS_STREAM_RE.test(methodSrc)) continue;

          const maxLine = Math.min(end, numCodeLines);
          for (let i = start - 1; i < maxLine; i++) {
            const ln = i + 1;
            if (reported.has(ln)) continue;
            const src = codeLines[i];
            const match = JS_WHOLE_LOAD_RE.exec(src);
            if (!match) continue;

            const methodName = match[0].replace(/\s*\(.*/, '').trim();
            wholeFileReads.push({ line: ln, method: methodName });
            reported.add(ln);

            ctx.addFinding({
              id: `missing-stream-${file}-${ln}`,
              pass: this.name,
              category: this.category,
              rule_id: this.name,
              severity: 'low',
              level: 'note',
              message:
                `\`${methodName}()\` loads the entire file/response into memory. ` +
                `Use a streaming API for large payloads.`,
              file,
              line: ln,
              snippet: src.trim(),
              fix:
                'Replace with fs.createReadStream / response.body (async iterator) ' +
                'to process data in chunks',
              evidence: { method: methodName },
            });
          }
        }
      }

      // Also check top-level code (outside any class/method) in loose JS files
      if (graph.ir.types.length === 0) {
        if (!JS_STREAM_RE.test(code)) {
          for (let i = 0; i < codeLines.length; i++) {
            const ln = i + 1;
            if (reported.has(ln)) continue;
            const src = codeLines[i];
            const match = JS_WHOLE_LOAD_RE.exec(src);
            if (!match) continue;

            const methodName = match[0].replace(/\s*\(.*/, '').trim();
            wholeFileReads.push({ line: ln, method: methodName });
            reported.add(ln);

            ctx.addFinding({
              id: `missing-stream-${file}-${ln}`,
              pass: this.name,
              category: this.category,
              rule_id: this.name,
              severity: 'low',
              level: 'note',
              message:
                `\`${methodName}()\` loads the entire file/response into memory. ` +
                `Use a streaming API for large payloads.`,
              file,
              line: ln,
              snippet: src.trim(),
              fix:
                'Replace with fs.createReadStream / response.body (async iterator) ' +
                'to process data in chunks',
              evidence: { method: methodName },
            });
          }
        }
      }
    } else if (language === 'java') {
      for (let i = 0; i < codeLines.length; i++) {
        const ln = i + 1;
        if (reported.has(ln)) continue;
        const src = codeLines[i];
        const match = JAVA_WHOLE_READ_RE.exec(src);
        if (!match) continue;

        const matchText = match[0].replace(/\s*\(.*/, '').trim();
        wholeFileReads.push({ line: ln, method: matchText });
        reported.add(ln);

        ctx.addFinding({
          id: `missing-stream-${file}-${ln}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          severity: 'low',
          level: 'note',
          message:
            `Whole-file read at line ${ln}: \`${matchText}\` loads the entire file into memory. ` +
            `Consider NIO Channels or InputStream for large files.`,
          file,
          line: ln,
          snippet: src.trim(),
          fix:
            'Use Files.lines() for line streaming, or InputStream / NIO channels for byte streaming',
          evidence: { method: matchText },
        });
      }
    } else if (language === 'python') {
      for (let i = 0; i < codeLines.length; i++) {
        const ln = i + 1;
        if (reported.has(ln)) continue;
        const src = codeLines[i];
        if (!PYTHON_WHOLE_READ_RE.test(src)) continue;

        // Skip comment lines
        if (/^\s*#/.test(src)) continue;

        wholeFileReads.push({ line: ln, method: 'read' });
        reported.add(ln);

        ctx.addFinding({
          id: `missing-stream-${file}-${ln}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          severity: 'low',
          level: 'note',
          message:
            `\`.read()\` loads the entire file into memory. ` +
            `Iterate over the file object instead for line-by-line streaming.`,
          file,
          line: ln,
          snippet: src.trim(),
          fix: "Iterate the file object: `for line in f:` instead of `data = f.read()`",
          evidence: { method: 'read' },
        });
      }
    }

    return { wholeFileReads };
  }
}
