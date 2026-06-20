/**
 * Pass: weak-password-encoding (CWE-261, category: security)
 *
 * Detects use of an encoding (base64 / hex) on a credential-named identifier.
 * Encoding is NOT encryption — base64-encoding a password before storing or
 * transmitting it provides no confidentiality. Common anti-pattern.
 *
 * Detection per language:
 *   Python:
 *     - `base64.b64encode(password)` / `.urlsafe_b64encode(...)`
 *     - `binascii.hexlify(password)`
 *   JS/TS:
 *     - `Buffer.from(password).toString('base64')` / `.toString('hex')`
 *     - `btoa(password)`
 *   Java:
 *     - `Base64.getEncoder().encodeToString(passwordBytes)`
 *     - `Base64.getUrlEncoder().encodeToString(...)`
 *     - `Hex.encodeHexString(passwordBytes)`
 *   Go:
 *     - `base64.StdEncoding.EncodeToString(passwordBytes)`
 *     - `hex.EncodeToString(...)`
 *
 * FP-guard: skip when the encoded value is part of an HTTP Basic auth
 * header construction (`"Basic " + base64(...)`) — that IS the spec.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';
import {
  argLooksLikeCredential,
  literalAt,
} from './_credential-helpers.js';

export interface WeakPasswordEncodingResult {
  findings: Array<{
    line: number;
    language: string;
    api: string;
  }>;
}

function isBasicAuthContext(call: CallInfo, code: string): boolean {
  // Look at the source line for "Basic " literal nearby — heuristic
  // for HTTP Basic auth construction where base64 is part of the spec.
  const line = call.location.line;
  if (line < 1) return false;
  const lines = code.split('\n');
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  const window = lines.slice(start, end).join('\n');
  return /["'`]Basic\s/i.test(window);
}

export class WeakPasswordEncodingPass implements AnalysisPass<WeakPasswordEncodingResult> {
  readonly name = 'weak-password-encoding';
  readonly category = 'security' as const;

  run(ctx: PassContext): WeakPasswordEncodingResult {
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;
    const findings: WeakPasswordEncodingResult['findings'] = [];

    for (const call of graph.ir.calls) {
      const api = this.detect(call, language);
      if (!api) continue;
      if (isBasicAuthContext(call, code)) continue;

      const line = call.location.line;
      findings.push({ line, language, api });

      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-261',
        severity: 'medium',
        level: 'warning',
        message:
          `Credential encoded via \`${api}\` — encoding is NOT encryption. ` +
          'Base64/hex provide no confidentiality; anyone with the encoded value can decode it.',
        file,
        line,
        fix:
          'For storage, use a password hash (Argon2id / bcrypt). ' +
          'For transport, use TLS. For symmetric secrecy, use authenticated encryption (AES-GCM).',
        evidence: { api, language },
      });
    }

    return { findings };
  }

  private detect(call: CallInfo, language: string): string | null {
    const method = call.method_name ?? '';
    const receiver = call.receiver ?? '';
    const recvLower = receiver.toLowerCase();

    const arg0 = call.arguments.find((a) => a.position === 0);

    if (language === 'python') {
      // base64.b64encode(password)
      if (recvLower === 'base64' &&
          (method === 'b64encode' || method === 'urlsafe_b64encode' ||
           method === 'standard_b64encode')) {
        if (argLooksLikeCredential(arg0)) return `base64.${method}`;
      }
      // binascii.hexlify(password)
      if (recvLower === 'binascii' && method === 'hexlify') {
        if (argLooksLikeCredential(arg0)) return 'binascii.hexlify';
      }
    }

    if (language === 'javascript' || language === 'typescript') {
      // Buffer.from(password).toString('base64')
      if (method === 'toString') {
        const encoding = literalAt(call, 0);
        if (encoding === 'base64' || encoding === 'hex' || encoding === 'base64url') {
          // Receiver expression should look like `Buffer.from(<credential>)`.
          // Conservative: check if receiver text contains "Buffer.from" and a
          // credential keyword.
          const recv = (receiver ?? '').toLowerCase();
          if (recv.includes('buffer.from') &&
              /(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key|access[_-]?key|credential)/i
                .test(receiver ?? '')) {
            return `Buffer.from().toString('${encoding}')`;
          }
        }
      }
      // btoa(password)
      if (method === 'btoa' && receiver === '') {
        if (argLooksLikeCredential(arg0)) return 'btoa';
      }
    }

    if (language === 'java') {
      // Base64.getEncoder().encodeToString(passwordBytes)
      // Or Base64.getUrlEncoder().encodeToString(...).
      if (method === 'encodeToString') {
        const recv = (receiver ?? '').toLowerCase();
        if (recv.includes('encoder') || recv.includes('base64')) {
          // arg[0] expr typically looks like `password.getBytes()`.
          const expr = (arg0?.expression ?? '').trim();
          const head = expr.split(/[.\s(]/, 1)[0] ?? '';
          if (argLooksLikeCredential({ position: 0, expression: head, variable: head })) {
            return 'Base64.encodeToString';
          }
        }
      }
      // Hex.encodeHexString(passwordBytes)
      if (method === 'encodeHexString' &&
          (receiver === 'Hex' || receiver.endsWith('.Hex'))) {
        const expr = (arg0?.expression ?? '').trim();
        const head = expr.split(/[.\s(]/, 1)[0] ?? '';
        if (argLooksLikeCredential({ position: 0, expression: head, variable: head })) {
          return 'Hex.encodeHexString';
        }
      }
    }

    if (language === 'go') {
      // base64.StdEncoding.EncodeToString(passwordBytes)
      if (method === 'EncodeToString') {
        const recv = (receiver ?? '').toLowerCase();
        if (recv.includes('base64') || recv.includes('hex') ||
            recv.includes('encoding')) {
          const expr = (arg0?.expression ?? '').trim();
          // Strip `[]byte(...)` wrapper.
          const inner = expr.replace(/^\[\]byte\s*\(\s*/, '').replace(/\s*\)\s*$/, '');
          const head = inner.split(/[.\s(]/, 1)[0] ?? '';
          if (argLooksLikeCredential({ position: 0, expression: head, variable: head })) {
            return recv.includes('hex') ? 'hex.EncodeToString' : 'base64.EncodeToString';
          }
        }
      }
    }

    return null;
  }
}
