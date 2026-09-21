/**
 * Modelled-CWE export (cognium-dev#393).
 *
 * Which weakness classes does the taint engine have a model for? Anything that
 * scores the engine against a CWE-labelled corpus needs the answer, and a
 * hand-kept list drifts and can be tuned. This derives it from the same runtime
 * registries the analyzer matches against, so it is always the truth for the
 * installed version and grows as sinks are added.
 *
 * "Modelled" is deliberately narrow: a CWE some SINK pattern is registered
 * under. Non-taint pattern passes (weak crypto, missing headers, resource
 * leaks …) stamp their CWE on each finding and have no registry to enumerate,
 * so they are out of this export rather than half-listed.
 */

import { DEFAULT_SINKS } from './config-loader.js';
import { createBuiltinPlugins } from '../languages/plugins/index.js';

/**
 * Ids an advisory may carry for a class the engine models under another id —
 * a child or sibling that reaches the same sink family. Keyed advisory-side,
 * valued with the modelled id. Kept short and literal on purpose: each entry
 * widens what counts as in scope, so each is a claim someone can check.
 */
export const RELATED_CWE: Readonly<Record<string, string>> = Object.freeze({
  'CWE-23': 'CWE-22',   // relative path traversal
  'CWE-36': 'CWE-22',   // absolute path traversal
  'CWE-73': 'CWE-22',   // external control of file name or path
  'CWE-77': 'CWE-78',   // command injection (generic) -> OS command injection
  'CWE-88': 'CWE-78',   // argument injection
  'CWE-80': 'CWE-79',   // basic XSS
  'CWE-564': 'CWE-89',  // SQL injection: Hibernate
  'CWE-95': 'CWE-94',   // eval injection
  'CWE-917': 'CWE-94',  // expression language injection
  'CWE-1336': 'CWE-94', // template engine injection
  'CWE-93': 'CWE-113',  // CRLF injection -> HTTP response splitting
  'CWE-91': 'CWE-643',  // XML injection -> XPath injection
  'CWE-776': 'CWE-611', // entity expansion -> external entities (same parser config)
});

export interface ModelledCwes {
  /** CWEs at least one registered sink pattern carries, sorted numerically. */
  sinkCwes: string[];
  /** Advisory-side ids that map onto a modelled class; see `RELATED_CWE`. */
  related: Readonly<Record<string, string>>;
}

const byNumber = (a: string, b: string): number =>
  Number(a.slice(4)) - Number(b.slice(4));

/** The engine's modelled taint classes, derived from the live sink registries. */
export function getModelledCwes(): ModelledCwes {
  const cwes = new Set<string>();
  for (const sink of DEFAULT_SINKS) if (sink.cwe) cwes.add(sink.cwe);
  for (const plugin of createBuiltinPlugins()) {
    for (const sink of plugin.getBuiltinSinks()) if (sink.cwe) cwes.add(sink.cwe);
  }
  return { sinkCwes: [...cwes].sort(byNumber), related: RELATED_CWE };
}

/**
 * Is `cwe` a class the taint engine models, directly or through `RELATED_CWE`?
 * A related id counts only while the id it maps to is itself still modelled.
 */
export function isModelledCwe(cwe: string, modelled: ModelledCwes = getModelledCwes()): boolean {
  const direct = new Set(modelled.sinkCwes);
  if (direct.has(cwe)) return true;
  const parent = modelled.related[cwe];
  return parent !== undefined && direct.has(parent);
}
