/**
 * Node `crypto` module bindings for the JS/TS crypto rule family
 * (weak-hash CWE-328, weak-crypto CWE-327, weak-password-hash CWE-916).
 *
 * Those passes match `crypto.<api>(...)` by the receiver text `crypto`.
 * The same API reached any other way was not reported:
 *
 *   import { createHash } from 'crypto';          createHash('md5')
 *   import { createHash as h } from 'node:crypto'; h('md5')
 *   const { createCipheriv } = require('crypto');  createCipheriv('des-cbc', k, iv)
 *   import * as nodeCrypto from 'crypto';          nodeCrypto.createHash('sha1')
 *   const c = require('crypto');                   c.createHash('md5')
 *   require('crypto').createHash('md5')
 *
 * `cryptoCallAsMember` rewrites such a call to the `crypto.<api>` shape the
 * passes already match. A name counts only when this file binds it to the
 * `crypto` / `node:crypto` module; a local function or an import from any
 * other package with the same name (`createHash` from a hashing library)
 * is left alone.
 *
 * Precision first, two exclusions:
 *   - a TypeScript type-only import (`import type { createHash }`,
 *     `import { type createHash }`) binds no value, so it binds nothing here;
 *   - a name the file declares again anywhere — a parameter, a local
 *     `const`/`let`/`var`, an inner function — is dropped for the whole
 *     file. The declaration may shadow the import in the scope the call is
 *     in, and the IR has no scope tree to tell, so the call is not rewritten.
 *     The declaration that comes from the import itself
 *     (`const c = require('crypto')`, on the import's own line) does not count.
 */

import type { CallInfo, DFG, ImportInfo, TypeInfo } from '../../types/index.js';

const CRYPTO_MODULES: ReadonlySet<string> = new Set(['crypto', 'node:crypto']);

const REQUIRE_CRYPTO_RE = /^require\(\s*(['"])(?:node:)?crypto\1\s*\)$/;

export interface JsCryptoBindings {
  /** Local names bound to the whole module (namespace, default or `require` result). */
  modules: ReadonlySet<string>;
  /** Local name → exported API name, for named imports / destructured requires. */
  named: ReadonlyMap<string, string>;
}

/** The parts of the file's IR that declare names: DFG defs, functions and their parameters. */
export interface JsDeclarations {
  dfg?: Pick<DFG, 'defs'> | null;
  types?: readonly Pick<TypeInfo, 'name' | 'methods'>[] | null;
}

export function jsCryptoBindings(
  imports: readonly ImportInfo[] | undefined,
  declarations?: JsDeclarations,
): JsCryptoBindings {
  const modules = new Set<string>();
  const named = new Map<string, string>();
  const importLine = new Map<string, number | null>();
  for (const imp of imports ?? []) {
    if (!imp.from_package || !CRYPTO_MODULES.has(imp.from_package)) continue;
    if (imp.is_type_only) continue;
    if (imp.is_wildcard || imp.imported_name === '*' || imp.imported_name === 'default') {
      if (imp.alias) {
        modules.add(imp.alias);
        importLine.set(imp.alias, imp.line_number);
      }
      continue;
    }
    const local = imp.alias ?? imp.imported_name;
    named.set(local, imp.imported_name);
    importLine.set(local, imp.line_number);
  }
  if (declarations && importLine.size > 0) {
    for (const name of redeclaredNames(importLine, declarations)) {
      modules.delete(name);
      named.delete(name);
    }
  }
  return { modules, named };
}

/** Bound names the file declares again, other than by the import itself. */
function redeclaredNames(importLine: ReadonlyMap<string, number | null>, decl: JsDeclarations): Set<string> {
  const out = new Set<string>();
  for (const def of decl.dfg?.defs ?? []) {
    if (!importLine.has(def.variable)) continue;
    if (def.kind === 'local' && def.line === importLine.get(def.variable)) continue;
    out.add(def.variable);
  }
  for (const type of decl.types ?? []) {
    for (const method of type.methods) {
      // A function declaration (synthetic `<module>` type) binds its name;
      // a class method does not, only its parameters do.
      if (type.name === '<module>' && importLine.has(method.name)) out.add(method.name);
      for (const param of method.parameters) {
        if (importLine.has(param.name)) out.add(param.name);
      }
    }
  }
  return out;
}

/**
 * The call rewritten as `crypto.<api>(...)` when it reaches the crypto
 * module through a binding other than the literal receiver `crypto`;
 * otherwise the call unchanged.
 */
export function cryptoCallAsMember(call: CallInfo, bindings: JsCryptoBindings): CallInfo {
  const receiver = (call.receiver ?? '').trim();
  if (receiver === 'crypto') return call;
  if (!receiver) {
    const api = bindings.named.get(call.method_name);
    return api ? { ...call, receiver: 'crypto', method_name: api } : call;
  }
  if (bindings.modules.has(receiver) || REQUIRE_CRYPTO_RE.test(receiver)) {
    return { ...call, receiver: 'crypto' };
  }
  return call;
}
