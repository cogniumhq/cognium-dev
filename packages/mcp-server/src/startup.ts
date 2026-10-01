/**
 * The startup lines.
 *
 * Pure: it turns a `Discovery` into the lines to print, so the wording is
 * testable without starting a server. `bin.ts` writes them to stderr —
 * stdout belongs to the JSON-RPC stream and must stay clean.
 *
 * What gets said, and what does not: the loaded modules, the licence state,
 * whether an endpoint is configured, and any refusal. Never the token, never
 * the endpoint's value, never anything about a key.
 */

import type { Discovery } from './server.js';
import { SERVER_NAME, SERVER_VERSION } from './server.js';

export function startupLines(found: Discovery): string[] {
  const tag = `[${SERVER_NAME}]`;
  const lines: string[] = [];

  const modules =
    found.modules.length === 0
      ? 'none'
      : found.modules.map((m) => `${m.id}@${m.version} (${m.licence})`).join(', ');

  lines.push(
    `${tag} ${SERVER_VERSION} · circle-ir ${found.circleIr} · licence ${found.enablement.state} · modules ${modules}` +
      (found.enablement.endpoint ? ' · endpoint configured' : ''),
  );

  // One notice in the extended state, once per process, as the terms require.
  if (found.enablement.state === 'extended') {
    const polyform = found.modules.filter((m) => /polyform/i.test(m.licence));
    if (polyform.length > 0) {
      lines.push(
        `${tag} ${polyform.map((m) => m.id).join(', ')} is licensed for non-commercial use. ` +
          `Run \`cognium license set <token>\` for commercial terms.`,
      );
    }
    if (found.enablement.licence.status === 'expired') {
      lines.push(`${tag} ${found.enablement.licence.detail}; serving with non-commercial terms.`);
    }
  }

  // A refusal costs only the module that was refused: say what is left, which
  // is the floor alone unless another module did load.
  const stillServing =
    found.modules.length === 0
      ? 'Serving the deterministic floor only.'
      : `Still serving the deterministic floor and ${found.modules.map((m) => m.id).join(', ')}.`;
  for (const refusal of found.refusals) {
    lines.push(`${tag} refused ${refusal.specifier}: ${refusal.reason}. ${stillServing}`);
  }

  return lines;
}
