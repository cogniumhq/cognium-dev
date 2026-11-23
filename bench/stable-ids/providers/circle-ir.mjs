// Provider: circle-ir's `ids@0.1` (deriveStableIds), and node ids from
// analyze() + assignNodeIds when the harness asks for them (--nodes).
//
// Loads $CIRCLE_IR, or this checkout's packages/circle-ir/dist/index.js
// (`npm run build:all` first: the parsers live in dist/wasm/). To measure ids
// exposed some other way, copy this file and change `derive`.

import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const name = 'circle-ir';

const HERE = dirname(fileURLToPath(import.meta.url));
const entry = process.env.CIRCLE_IR ?? join(HERE, '..', '..', '..', 'packages', 'circle-ir', 'dist', 'index.js');
let libPromise = null;

/** The library, with its parsers initialised (deriveStableIds parses, so it needs them too). */
function load() {
  libPromise ??= (async () => {
    if (!existsSync(entry)) throw new Error(`circle-ir provider: ${entry} not found; run \`npm run build:all\` or set CIRCLE_IR`);
    const mod = await import(pathToFileURL(entry).href);
    if (typeof mod.deriveStableIds !== 'function') throw new Error(`circle-ir provider: ${entry} has no deriveStableIds`);
    if (typeof mod.initAnalyzer === 'function') await mod.initAnalyzer();
    else if (typeof mod.initParser === 'function') await mod.initParser();
    return mod;
  })();
  return libPromise;
}

function language(file) {
  return file.endsWith('.tsx') ? 'tsx' : 'typescript';
}

export async function describe() {
  const l = await load();
  return { provider: name, scheme: l.STABLE_ID_SCHEME ?? null, entry };
}

/** `{ decls: [{ id, body_id, name, kind, start_line, end_line, parent }], partial }` for one file. */
export async function derive(code, file) {
  const l = await load();
  return l.deriveStableIds(code, file, language(file));
}

/** Node ids of one file grouped by the body id they are keyed under, or null when unsupported. */
export async function nodes(code, file, ids) {
  const l = await load();
  if (typeof l.analyze !== 'function' || typeof l.assignNodeIds !== 'function') return null;
  const ir = await l.analyze(code, file, language(file));
  const n = l.assignNodeIds(ids, ir);
  const byBody = new Map();
  for (const id of [...n.cfg_blocks, ...n.dfg_defs, ...n.dfg_uses, ...n.calls]) {
    if (id === null) continue;
    const body = id.slice(0, id.lastIndexOf('/'));
    const g = byBody.get(body);
    if (g) g.push(id); else byBody.set(body, [id]);
  }
  return byBody;
}
