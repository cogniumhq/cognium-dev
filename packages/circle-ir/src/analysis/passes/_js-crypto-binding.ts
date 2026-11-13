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
 */

import type { CallInfo, ImportInfo } from '../../types/index.js';

const CRYPTO_MODULES: ReadonlySet<string> = new Set(['crypto', 'node:crypto']);

const REQUIRE_CRYPTO_RE = /^require\(\s*(['"])(?:node:)?crypto\1\s*\)$/;

export interface JsCryptoBindings {
  /** Local names bound to the whole module (namespace, default or `require` result). */
  modules: ReadonlySet<string>;
  /** Local name → exported API name, for named imports / destructured requires. */
  named: ReadonlyMap<string, string>;
}

export function jsCryptoBindings(imports: readonly ImportInfo[] | undefined): JsCryptoBindings {
  const modules = new Set<string>();
  const named = new Map<string, string>();
  for (const imp of imports ?? []) {
    if (!imp.from_package || !CRYPTO_MODULES.has(imp.from_package)) continue;
    if (imp.is_wildcard || imp.imported_name === '*' || imp.imported_name === 'default') {
      if (imp.alias) modules.add(imp.alias);
      continue;
    }
    named.set(imp.alias ?? imp.imported_name, imp.imported_name);
  }
  return { modules, named };
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
