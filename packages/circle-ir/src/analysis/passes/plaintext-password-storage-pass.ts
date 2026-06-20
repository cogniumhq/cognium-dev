/**
 * Pass: plaintext-password-storage (CWE-256, category: security)
 *
 * Detects writing a credential-named identifier to a persistent store
 * (file, KV store, cookie, database) without first passing it through a
 * cryptographic hash / KDF.
 *
 * Detection per language:
 *   Python:
 *     - `open(...).write(password)` / `f.write(password)`
 *     - `pickle.dump(password, ...)` / `json.dump(...)` / `yaml.dump(...)`
 *     - `redis.set(key, password)`
 *   JS/TS:
 *     - `fs.writeFile|writeFileSync|appendFile(path, password)`
 *     - `localStorage.setItem(key, password)` / `sessionStorage.setItem`
 *     - `redis.set(key, password)`
 *   Java:
 *     - `Files.write|writeString(path, password)`
 *     - `FileWriter.write(password)`
 *   Go:
 *     - `os.WriteFile(name, []byte(password), ...)`
 *     - `f.WriteString(password)` / `f.Write([]byte(password))`
 *
 * Heuristic for "not hashed": intraprocedural — walk all calls earlier
 * in the same `in_method` scope; if any of them is a known hash/KDF
 * (see _credential-helpers `isHashFunctionCall`) and consumes the
 * credential identifier, suppress.
 *
 * This is intentionally lightweight (no full DFG); FP risk skewed toward
 * recall loss for cross-function hashing (controller → service.hash →
 * repo.store), which is acceptable for v1.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';
import {
  argLooksLikeCredential,
  priorHashOf,
} from './_credential-helpers.js';

interface WriteSpec {
  /** Position of the credential value in the call argument list. */
  credPos: number;
  /** Human-readable API label for the finding. */
  api: string;
}

export interface PlaintextPasswordStorageResult {
  findings: Array<{
    line: number;
    language: string;
    api: string;
    identifier: string;
  }>;
}

function isWriteStorageCall(
  call: CallInfo,
  language: string,
): WriteSpec | null {
  const method = call.method_name ?? '';
  const receiver = call.receiver ?? '';
  const recvLower = receiver.toLowerCase();

  if (language === 'python') {
    // open(...).write(pw) — receiver is a file handle; we approximate by
    // method name `write` and check arg credential below.
    if (method === 'write' || method === 'writelines') {
      return { credPos: 0, api: `<file>.${method}` };
    }
    if ((recvLower === 'pickle' || recvLower === 'json' || recvLower === 'yaml') &&
        (method === 'dump' || method === 'dumps')) {
      return { credPos: 0, api: `${receiver}.${method}` };
    }
    if (recvLower === 'redis' && (method === 'set' || method === 'setex' || method === 'hset')) {
      return { credPos: 1, api: `redis.${method}` };
    }
  }

  if (language === 'javascript' || language === 'typescript') {
    if ((recvLower === 'fs' || recvLower.endsWith('.fs')) &&
        (method === 'writeFile' || method === 'writeFileSync' ||
         method === 'appendFile' || method === 'appendFileSync')) {
      return { credPos: 1, api: `fs.${method}` };
    }
    if ((recvLower === 'localstorage' || recvLower === 'sessionstorage') &&
        method === 'setItem') {
      return { credPos: 1, api: `${receiver}.setItem` };
    }
    if (recvLower === 'redis' && (method === 'set' || method === 'setex' || method === 'hset')) {
      return { credPos: 1, api: `redis.${method}` };
    }
  }

  if (language === 'java') {
    if ((receiver === 'Files' || receiver.endsWith('.Files')) &&
        (method === 'write' || method === 'writeString')) {
      return { credPos: 1, api: `Files.${method}` };
    }
    // FileWriter.write(pw) — instance call, single arg.
    if (method === 'write') {
      // Heuristic: receiver name contains "writer" / "file" / "stream".
      const lc = (receiver ?? '').toLowerCase();
      if (lc.includes('writer') || lc.includes('file') || lc.includes('stream')) {
        return { credPos: 0, api: `${receiver}.write` };
      }
    }
  }

  if (language === 'go') {
    if (receiver === 'os' || receiver.endsWith('/os')) {
      if (method === 'WriteFile') return { credPos: 1, api: 'os.WriteFile' };
    }
    if (receiver === 'ioutil' || receiver.endsWith('/ioutil')) {
      if (method === 'WriteFile') return { credPos: 1, api: 'ioutil.WriteFile' };
    }
    if (method === 'WriteString' || method === 'Write') {
      return { credPos: 0, api: `<file>.${method}` };
    }
  }

  return null;
}

export class PlaintextPasswordStoragePass
  implements AnalysisPass<PlaintextPasswordStorageResult>
{
  readonly name = 'plaintext-password-storage';
  readonly category = 'security' as const;

  run(ctx: PassContext): PlaintextPasswordStorageResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: PlaintextPasswordStorageResult['findings'] = [];

    // Group calls by in_method for cheap prior-hash lookup.
    const callsByScope = new Map<string, CallInfo[]>();
    for (const call of graph.ir.calls) {
      const scope = call.in_method ?? '<top>';
      const arr = callsByScope.get(scope) ?? [];
      arr.push(call);
      callsByScope.set(scope, arr);
    }

    for (const call of graph.ir.calls) {
      const spec = isWriteStorageCall(call, language);
      if (!spec) continue;

      const credArg = call.arguments.find((a) => a.position === spec.credPos);
      if (!credArg) continue;
      if (!argLooksLikeCredential(credArg)) continue;

      // Resolve the credential identifier name.
      const identExpr = (credArg.expression ?? '').trim();
      const head = identExpr.split(/[.\s(]/, 1)[0] ?? '';
      const identifier = credArg.variable ?? head;
      if (!identifier) continue;

      // Suppress if the identifier was hashed earlier in the same scope.
      const scope = call.in_method ?? '<top>';
      const scopeCalls = callsByScope.get(scope) ?? [];
      const prior = scopeCalls.filter((c) => c.location.line < call.location.line);
      if (priorHashOf(identifier, prior)) continue;

      // Suppress if the credArg expression itself contains a hash call
      // inline: `f.write(bcrypt.hashpw(pw))`.
      if (/\b(?:hashpw|hash|sha\d+|md5|bcrypt|argon2|pbkdf2|digest)\b/i
            .test(credArg.expression ?? '')) {
        continue;
      }

      const line = call.location.line;
      findings.push({ line, language, api: spec.api, identifier });

      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-256',
        severity: 'high',
        level: 'warning',
        message:
          `Credential \`${identifier}\` written in plaintext via \`${spec.api}\`. ` +
          'Passwords / secrets must be hashed (Argon2id, bcrypt) before storage.',
        file,
        line,
        fix:
          'Hash the credential with Argon2id / bcrypt before writing it to ' +
          'disk, cookie, KV store, or database.',
        evidence: { identifier, api: spec.api, language },
      });
    }

    return { findings };
  }
}
