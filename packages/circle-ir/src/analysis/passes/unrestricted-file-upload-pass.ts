/**
 * Pass: unrestricted-file-upload (CWE-434, category: security)
 *
 * Detects when an HTTP-uploaded file is saved to disk WITHOUT a filename
 * allow-list (extension check) or `secure_filename` normalization.
 *
 * Detection (per language):
 *
 *   Java (Spring MultipartFile / Servlet Part):
 *     - `file.transferTo(new File(dir, file.getOriginalFilename()))`
 *     - `Files.copy(part.getInputStream(), Path.of(dir, part.getSubmittedFileName()))`
 *     - Without preceding `ALLOWED_*.contains(ext)` or
 *       `FilenameUtils.getExtension(name)` + check.
 *
 *   JS/TS (multer / express-fileupload):
 *     - `multer({ dest: '…' })` with NO `fileFilter` option.
 *     - `fs.writeFile(path, req.file.buffer)` / `req.files.x.mv(path)`
 *       without prior `path.extname` allow-list check.
 *
 *   Python (Flask / Django / FastAPI):
 *     - `f.save(os.path.join(UPLOAD_DIR, f.filename))` without prior
 *       `secure_filename(f.filename)` wrapping.
 *
 *   Go:
 *     - `io.Copy(dst, file)` where `dst = os.Create(fileHeader.Filename)`
 *       without an extension allow-list.
 *
 * The pass is intentionally conservative — it only fires when an upload-name
 * expression flows directly into a save sink in the same function and no
 * known allow-list / canonicalizer call appears earlier in the function.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

export interface UnrestrictedFileUploadResult {
  findings: Array<{ line: number; api: string; language: string }>;
}

/** Receivers / expressions that look like an uploaded file value. */
const UPLOAD_NAME_RE =
  /(?:getOriginalFilename|getSubmittedFileName|originalname|originalName|\.filename|\.Filename|FileHeader\.Filename|UploadFile)/;

/** Identifier-level allow-list / canonicalization calls that defang upload paths. */
const FILE_SAFE_CALL_RE =
  /(?:secure_filename|FilenameUtils\.getExtension|\.lastIndexOf\(['"]\.['"]\)|ALLOWED_EXT|ALLOWED_EXTENSIONS|allowedExtensions|\bfileFilter\b|filepath\.Ext|path\.extname)/;

function lineWindow(code: string, startLine: number, endLine: number): string {
  const lines = code.split('\n');
  const s = Math.max(0, startLine - 1);
  const e = Math.min(lines.length, endLine);
  return lines.slice(s, e).join('\n');
}

function callHasUploadName(call: CallInfo): boolean {
  for (const a of call.arguments) {
    const expr = (a.expression ?? a.variable ?? '').trim();
    if (UPLOAD_NAME_RE.test(expr)) return true;
  }
  // Receiver too (e.g. multipart `file.transferTo(...)`).
  if (UPLOAD_NAME_RE.test(call.receiver ?? '')) return true;
  return false;
}

export class UnrestrictedFileUploadPass implements AnalysisPass<UnrestrictedFileUploadResult> {
  readonly name = 'unrestricted-file-upload';
  readonly category = 'security' as const;

  run(ctx: PassContext): UnrestrictedFileUploadResult {
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;
    const findings: UnrestrictedFileUploadResult['findings'] = [];

    // Build per-function safety windows: a function is "safe" if its body
    // contains any FILE_SAFE_CALL_RE marker. Used to suppress findings inside
    // that scope.
    const safeFunctionRanges: Array<{ start: number; end: number }> = [];
    for (const t of graph.ir.types) {
      for (const m of t.methods) {
        const body = lineWindow(code, m.start_line, m.end_line);
        if (FILE_SAFE_CALL_RE.test(body)) {
          safeFunctionRanges.push({ start: m.start_line, end: m.end_line });
        }
      }
    }

    const inSafeRange = (line: number): boolean => {
      for (const r of safeFunctionRanges) {
        if (line >= r.start && line <= r.end) return true;
      }
      // No method information — fall back to a ±20-line window around the call.
      const win = lineWindow(code, Math.max(1, line - 20), line + 5);
      return FILE_SAFE_CALL_RE.test(win);
    };

    // --- Per-language detection -----------------------------------------------

    if (language === 'java') {
      for (const call of graph.ir.calls) {
        const m = call.method_name ?? '';
        // file.transferTo(...)
        if (m === 'transferTo' && callHasUploadName(call)) {
          if (inSafeRange(call.location.line)) continue;
          this.emit(ctx, findings, file, call.location.line, language,
                    'MultipartFile.transferTo(<original filename>)');
          continue;
        }
        // Files.copy(getInputStream, Path.of(dir, getOriginalFilename))
        if (m === 'copy' && (call.receiver === 'Files' || (call.receiver ?? '').endsWith('.Files'))) {
          if (callHasUploadName(call)) {
            if (inSafeRange(call.location.line)) continue;
            this.emit(ctx, findings, file, call.location.line, language,
                      'Files.copy(input, Path.of(dir, <original filename>))');
          }
        }
      }
    }

    if (language === 'javascript' || language === 'typescript') {
      for (const call of graph.ir.calls) {
        const m = call.method_name ?? '';
        const rec = call.receiver ?? '';

        // multer({ dest: '...' }) — flag if same call object lacks fileFilter.
        if (m === 'multer' || (rec === '' && m === 'multer')) {
          const arg0 = call.arguments.find((a) => a.position === 0);
          const expr = (arg0?.expression ?? '').trim();
          if (/\bdest\s*:/.test(expr) && !/\bfileFilter\s*:/.test(expr)) {
            if (inSafeRange(call.location.line)) continue;
            this.emit(ctx, findings, file, call.location.line, language,
                      'multer({ dest }) without fileFilter');
            continue;
          }
        }

        // fs.writeFile(<path>, req.file.buffer) / req.files.x.mv(<path>)
        if (rec === 'fs' && (m === 'writeFile' || m === 'writeFileSync' || m === 'appendFile')) {
          if (callHasUploadName(call) ||
              call.arguments.some((a) => /\breq\.file(?:s)?\b/.test((a.expression ?? a.variable ?? '')))) {
            if (inSafeRange(call.location.line)) continue;
            this.emit(ctx, findings, file, call.location.line, language,
                      `fs.${m}(<path>, req.file.buffer)`);
          }
        }
      }
    }

    if (language === 'python') {
      for (const call of graph.ir.calls) {
        const m = call.method_name ?? '';
        // f.save(os.path.join(UPLOAD_DIR, f.filename))
        if (m === 'save') {
          const rec = call.receiver ?? '';
          // Accept any receiver that looks file-ish or empty (`f.save`, `file.save`).
          if (!/^(f|file|upload|attachment)$/i.test(rec) && rec !== '') continue;
          if (!callHasUploadName(call)) continue;
          if (inSafeRange(call.location.line)) continue;
          this.emit(ctx, findings, file, call.location.line, language,
                    'f.save(<dir>, f.filename) without secure_filename');
        }
      }
    }

    if (language === 'go') {
      for (const call of graph.ir.calls) {
        const m = call.method_name ?? '';
        const rec = call.receiver ?? '';
        // os.Create(header.Filename)
        if (rec === 'os' && (m === 'Create' || m === 'OpenFile')) {
          if (callHasUploadName(call)) {
            if (inSafeRange(call.location.line)) continue;
            this.emit(ctx, findings, file, call.location.line, language,
                      `os.${m}(<uploaded filename>)`);
          }
        }
        // ioutil.WriteFile(header.Filename, …)
        if ((rec === 'os' || rec === 'ioutil') && m === 'WriteFile') {
          if (callHasUploadName(call)) {
            if (inSafeRange(call.location.line)) continue;
            this.emit(ctx, findings, file, call.location.line, language,
                      `${rec}.WriteFile(<uploaded filename>, …)`);
          }
        }
      }
    }

    return { findings };
  }

  private emit(
    ctx: PassContext,
    findings: UnrestrictedFileUploadResult['findings'],
    file: string,
    line: number,
    language: string,
    api: string,
  ) {
    findings.push({ line, api, language });
    ctx.addFinding({
      id: `${this.name}-${file}-${line}`,
      pass: this.name,
      category: this.category,
      rule_id: this.name,
      cwe: 'CWE-434',
      severity: 'high',
      level: 'error',
      message:
        `File upload saved using untrusted name (${api}) — no extension allow-list or ` +
        'filename canonicalization detected. An attacker can upload a `.jsp`/`.php`/`.html` ' +
        'file and request it back, achieving RCE or stored XSS.',
      file,
      line,
      fix:
        'Validate the uploaded extension against an allow-list (e.g. ' +
        '`Set.of("png","jpg")`), then save with a sanitized filename. In Python use ' +
        '`werkzeug.utils.secure_filename`. In multer pass a `fileFilter`. Never ' +
        'concatenate the upload\'s original filename into a save path without ' +
        'validation.',
      evidence: { api, language },
    });
  }
}
