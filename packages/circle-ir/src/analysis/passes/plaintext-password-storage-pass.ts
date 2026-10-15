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
 * Python owner-only destinations (#672): a write whose file handle was obtained
 * from `os.open(path, flags, <owner-only mode>)` (directly or via `os.fdopen` /
 * `open(fd)`), or from a path/handle that an earlier `os.chmod` / `os.fchmod`
 * restricted to the owner (no group/other bits), is not reported — the secret
 * stays in a file only its owner can read.
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

/** Parse a Python integer literal (`0o600`, `0600`, `384`, `0x180`) or `stat.S_I*` mask; null when unknown. */
function pyModeValue(expr: string | null | undefined): number | null {
  const t = (expr ?? '').trim();
  if (!t) return null;
  if (/^0[oO][0-7]+$/.test(t)) return parseInt(t.slice(2), 8);
  if (/^0[0-7]+$/.test(t)) return parseInt(t, 8);
  if (/^0[xX][0-9a-fA-F]+$/.test(t)) return parseInt(t.slice(2), 16);
  if (/^\d+$/.test(t)) return parseInt(t, 10);
  // stat.S_IRUSR | stat.S_IWUSR — owner bits only; any group/other constant is not owner-only.
  const parts = t.split('|').map((x) => x.trim().replace(/^stat\./, ''));
  const USR: Record<string, number> = { S_IRUSR: 0o400, S_IWUSR: 0o200, S_IXUSR: 0o100, S_IRWXU: 0o700 };
  let v = 0;
  for (const p of parts) {
    if (p in USR) v |= USR[p]!;
    else if (/^S_I(?:R|W|X|RWX)(?:GRP|OTH|G|O)$/.test(p)) v |= 0o077;
    else return null;
  }
  return v;
}

/** True when `mode` grants nothing to group or other (and is not empty). */
const isOwnerOnlyMode = (mode: number | null): boolean =>
  mode !== null && mode > 0 && (mode & 0o077) === 0;

/** The `mode` argument of an `os.open` / `os.chmod` / `os.fchmod` call, owner-only? */
function callSetsOwnerOnlyMode(call: CallInfo): boolean {
  const recv = call.receiver ?? '';
  if (recv !== 'os') return false;
  const pos = call.method_name === 'open' ? 2 : call.method_name === 'chmod' || call.method_name === 'fchmod' ? 1 : -1;
  if (pos < 0) return false;
  const arg = call.arguments.find((a) => a.position === pos);
  return isOwnerOnlyMode(pyModeValue(arg?.literal ?? arg?.expression));
}

const IDENT = /^[A-Za-z_]\w*$/;
const firstArg = (c: CallInfo): string => (c.arguments.find((a) => a.position === 0)?.expression ?? '').trim();

/**
 * Python: was the file handle that `write` is called on created/opened with
 * owner-only permissions? Resolved from the handle's binding line
 * (`with <expr> as h`, `h = <expr>`), the calls on that line, and — for a
 * descriptor — the line that bound it.
 */
function pyWriteTargetsOwnerOnlyFile(call: CallInfo, scopeCalls: CallInfo[], lines: string[]): boolean {
  const receiver = (call.receiver ?? '').trim();
  const before = scopeCalls.filter((c) => c.location.line < call.location.line);
  const callsOn = (line: number) => scopeCalls.filter((c) => c.location.line === line);
  const bindingLine = (name: string, from: number): number | null => {
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(?:\\bas\\s+${esc}\\b|^\\s*${esc}\\s*=(?!=))`);
    for (let ln = from - 1; ln >= 1; ln--) {
      if (re.test(lines[ln - 1] ?? '')) return ln;
    }
    return null;
  };

  // Does the expression evaluated on `line` yield an owner-only file/descriptor?
  const ownerOnlyAt = (line: number, depth: number): boolean => {
    const here = callsOn(line);
    if (here.some((c) => c.method_name === 'open' && callSetsOwnerOnlyMode(c))) return true;
    for (const c of here) {
      // os.fdopen(fd, ...) / open(fd, ...) — follow a bare descriptor variable.
      if ((c.method_name === 'fdopen' && c.receiver === 'os') || (c.method_name === 'open' && !c.receiver)) {
        const a0 = firstArg(c);
        if (IDENT.test(a0) && depth < 3) {
          const bl = bindingLine(a0, line);
          if (bl !== null && ownerOnlyAt(bl, depth + 1)) return true;
        }
        // open(path, ...) — an earlier chmod of that same path expression.
        if (c.method_name === 'open' && a0) {
          if (before.some((p) => p.location.line < line && callSetsOwnerOnlyMode(p) && p.method_name === 'chmod' && firstArg(p) === a0)) return true;
        }
      }
    }
    return false;
  };

  // Receiver is an inline expression: `os.fdopen(os.open(...), "w").write(x)`.
  if (!receiver || !IDENT.test(receiver)) return ownerOnlyAt(call.location.line, 0);

  // os.fchmod(<handle>.fileno() | <fd>, owner-only) before the write.
  const bl = bindingLine(receiver, call.location.line);
  if (before.some((c) => c.method_name === 'fchmod' && callSetsOwnerOnlyMode(c) &&
      new RegExp(`\\b${receiver}\\b`).test(firstArg(c)))) return true;
  if (bl === null) return false;
  // os.fchmod(fd, owner-only) on the bare descriptor this handle wraps.
  const handleCalls = callsOn(bl);
  for (const c of handleCalls) {
    if ((c.method_name === 'fdopen' && c.receiver === 'os') || (c.method_name === 'open' && !c.receiver)) {
      const a0 = firstArg(c);
      if (IDENT.test(a0) && before.some((p) => p.method_name === 'fchmod' && callSetsOwnerOnlyMode(p) && firstArg(p) === a0)) return true;
    }
  }
  return ownerOnlyAt(bl, 0);
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
    const codeLines = language === 'python' ? ctx.code.split('\n') : [];

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

      // Python: the write lands in a file only its owner can read (#672).
      if (language === 'python' && spec.api.startsWith('<file>.') &&
          pyWriteTargetsOwnerOnlyFile(call, scopeCalls, codeLines)) {
        continue;
      }

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
