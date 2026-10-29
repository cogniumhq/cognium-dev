/**
 * Reader for `safe-construct-table@0.1`: a caller-supplied table that, for one
 * weakness class (CWE) in one language, lists the sink APIs of the class and
 * the constructs a fix may use at those sinks (`safe` or `weak` rows), each
 * with a `match` written in a small step vocabulary.
 *
 * The library ships no such table: it is an input. This module only parses
 * and validates one, and computes its digest. It never decides whether a
 * construct is adequate — a later matcher reports which row a sink matched,
 * and the caller decides.
 *
 * The reader is the schema pin. A table with any unknown key, a different
 * `format`, a bad enum value the matcher depends on, or a dangling reference
 * is **refused whole**, with every problem listed; no row is ever skipped.
 * Labels the matcher does not interpret (`remedy-class`, `context`,
 * `check-set`, `language`, `settles`, citation text) are passed through, so a
 * new label needs no library release; a new match key does.
 *
 * Pure: strings and bytes in, values out. Browser and Node compatible.
 */

import { parseAllDocuments } from 'yaml';
import { sha256Digest } from './sha256.js';

export const SAFE_CONSTRUCT_TABLE_FORMAT = 'safe-construct-table@0.1' as const;

// ---------------------------------------------------------------------------
// Types of an accepted table
// ---------------------------------------------------------------------------

/** Argument position: 0-based index, or `all` for any argument (varargs). */
export type ArgPosition = number | 'all';

export interface TableCall {
  /** Receiver type (or a supertype), fully qualified; `java.lang.Object` = any. */
  type: string;
  /** Method names; a trailing `*` matches a prefix, `*` alone matches any. Empty for a constructor. */
  methods: string[];
  arg?: ArgPosition;
  ctor?: boolean;
  static?: boolean;
  /** `<Type>.<method>` whose result is the receiver. */
  receiverFrom?: string;
}

export interface TableTemplate {
  engine: string;
  construct: string;
  attribute?: string;
  /** Accepted attribute values; `absent` stands for the attribute not being written. */
  value?: string[];
}

export type ArgIs = 'untainted' | 'tainted' | 'from-allowlist';
export type StepRole = 'sink-replacement' | 'binder' | 'sanitizer' | 'guard' | 'normalizer';

/** One step of a row's `match`. Keys are camel-cased from the table's kebab-case. */
export interface MatchStep {
  call?: TableCall;
  argIs?: ArgIs;
  argLiteralIn?: string[];
  role?: StepRole;
  on?: boolean;
  order?: [string, string];
  name?: string;
  template?: TableTemplate;
  sinkRemoved?: true;
  missing?: MatchStep;
  any?: MatchStep[];
  all?: MatchStep[];
}

export interface TableSink {
  id: string;
  call?: TableCall;
  template?: TableTemplate;
  note?: string;
}

export type ConstructClass = 'safe' | 'weak';

export interface ConstructRow {
  id: string;
  class: ConstructClass;
  /** Label passed through; not interpreted by the library. */
  remedyClass: string;
  appliesTo: string[];
  /** Label passed through; not interpreted by the library. */
  context?: string;
  match: MatchStep;
  level: 'SHOULD' | 'MUST';
  basis: 'cited' | 'own';
  sources: string[];
  residual?: string;
  note?: string;
  /** Table version in which the row was retired; a matcher skips retired rows. */
  retired?: string;
}

export interface TableSource {
  kind: string;
  publisher: string;
  title: string;
  url: string;
  fetched: string;
  quote: string;
  via?: string;
}

export interface SafeConstructTable {
  format: typeof SAFE_CONSTRUCT_TABLE_FORMAT;
  checkSet: string;
  cwe: number;
  cweListVersion: string;
  language: string;
  version: string;
  settles: string;
  sources: Record<string, TableSource>;
  sinks: TableSink[];
  /** Rows in file order. */
  constructs: ConstructRow[];
}

export type TableProblemCode =
  | 'parse-error'
  | 'unknown-format'
  | 'unknown-key'
  | 'missing-key'
  | 'bad-value'
  | 'dangling-ref'
  | 'duplicate-id';

export interface TableProblem {
  /** JSON-pointer-like location, e.g. `/constructs/3/match/all/1/role`. */
  path: string;
  code: TableProblemCode;
  message: string;
}

export type LoadTableResult =
  | { ok: true; digest: string; table: SafeConstructTable }
  | { ok: false; digest: string; format: string | null; problems: TableProblem[] };

// ---------------------------------------------------------------------------
// Accepted keys and values
// ---------------------------------------------------------------------------

const TOP_KEYS = ['format', 'check-set', 'cwe', 'cwe-list-version', 'language', 'version', 'settles', 'sources', 'sinks', 'constructs'];
const SOURCE_KEYS = ['kind', 'publisher', 'title', 'url', 'fetched', 'quote', 'via'];
const SOURCE_REQUIRED = ['kind', 'publisher', 'title', 'url', 'fetched', 'quote'];
const SINK_KEYS = ['id', 'call', 'template', 'note'];
const CALL_KEYS = ['type', 'methods', 'arg', 'ctor', 'static', 'receiver-from'];
const TEMPLATE_KEYS = ['engine', 'construct', 'attribute', 'value'];
const ROW_KEYS = ['id', 'class', 'remedy-class', 'applies-to', 'context', 'match', 'level', 'basis', 'sources', 'residual', 'note', 'retired'];
const ROW_REQUIRED = ['id', 'class', 'remedy-class', 'applies-to', 'match', 'level', 'basis', 'sources'];
const STEP_KEYS = ['call', 'arg-is', 'arg-literal-in', 'role', 'on', 'order', 'name', 'template', 'sink-removed', 'missing', 'any', 'all'];

const ARG_IS: readonly ArgIs[] = ['untainted', 'tainted', 'from-allowlist'];
const ROLES: readonly StepRole[] = ['sink-replacement', 'binder', 'sanitizer', 'guard', 'normalizer'];
const CLASSES: readonly ConstructClass[] = ['safe', 'weak'];
const LEVELS = ['SHOULD', 'MUST'] as const;
const BASES = ['cited', 'own'] as const;

type Plain = Record<string, unknown>;

function isMap(v: unknown): v is Plain {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

function isStringList(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(x => typeof x === 'string');
}

/** Collects problems while walking one table. */
class Checker {
  readonly problems: TableProblem[] = [];

  add(path: string, code: TableProblemCode, message: string): void {
    this.problems.push({ path, code, message });
  }

  /** Reports unknown keys and missing required keys; returns whether the value is a map. */
  keys(v: unknown, path: string, allowed: readonly string[], required: readonly string[] = []): v is Plain {
    if (!isMap(v)) {
      this.add(path, 'bad-value', 'expected a mapping');
      return false;
    }
    for (const k of Object.keys(v)) {
      if (!allowed.includes(k)) this.add(`${path}/${k}`, 'unknown-key', `unknown key "${k}"`);
    }
    for (const k of required) {
      if (v[k] === undefined) this.add(`${path}/${k}`, 'missing-key', `missing key "${k}"`);
    }
    return true;
  }

  string(v: unknown, path: string): string | undefined {
    if (v === undefined) return undefined;
    if (!isNonEmptyString(v)) {
      this.add(path, 'bad-value', 'expected a non-empty string');
      return undefined;
    }
    return v;
  }

  oneOf<T extends string>(v: unknown, path: string, allowed: readonly T[]): T | undefined {
    if (v === undefined) return undefined;
    if (typeof v !== 'string' || !(allowed as readonly string[]).includes(v)) {
      this.add(path, 'bad-value', `expected one of ${allowed.join(', ')}; got ${JSON.stringify(v)}`);
      return undefined;
    }
    return v as T;
  }

  bool(v: unknown, path: string): boolean | undefined {
    if (v === undefined) return undefined;
    if (typeof v !== 'boolean') {
      this.add(path, 'bad-value', 'expected true or false');
      return undefined;
    }
    return v;
  }

  stringList(v: unknown, path: string): string[] | undefined {
    if (v === undefined) return undefined;
    if (!isStringList(v)) {
      this.add(path, 'bad-value', 'expected a list of strings');
      return undefined;
    }
    return v;
  }

  call(v: unknown, path: string): TableCall | undefined {
    if (!this.keys(v, path, CALL_KEYS, ['type', 'methods'])) return undefined;
    const type = this.string(v.type, `${path}/type`);
    const methods = this.stringList(v.methods, `${path}/methods`);
    let arg: ArgPosition | undefined;
    if (v.arg !== undefined) {
      if (v.arg === 'all' || (typeof v.arg === 'number' && Number.isInteger(v.arg) && v.arg >= 0)) {
        arg = v.arg;
      } else {
        this.add(`${path}/arg`, 'bad-value', 'expected a 0-based index or "all"');
      }
    }
    const ctor = this.bool(v.ctor, `${path}/ctor`);
    const isStatic = this.bool(v.static, `${path}/static`);
    const receiverFrom = this.string(v['receiver-from'], `${path}/receiver-from`);
    if (type === undefined || methods === undefined) return undefined;
    const call: TableCall = { type, methods };
    if (arg !== undefined) call.arg = arg;
    if (ctor !== undefined) call.ctor = ctor;
    if (isStatic !== undefined) call.static = isStatic;
    if (receiverFrom !== undefined) call.receiverFrom = receiverFrom;
    return call;
  }

  template(v: unknown, path: string): TableTemplate | undefined {
    if (!this.keys(v, path, TEMPLATE_KEYS, ['engine', 'construct'])) return undefined;
    const engine = this.string(v.engine, `${path}/engine`);
    const construct = this.string(v.construct, `${path}/construct`);
    const attribute = this.string(v.attribute, `${path}/attribute`);
    let value: string[] | undefined;
    if (v.value !== undefined) {
      if (typeof v.value === 'string') value = [v.value];
      else value = this.stringList(v.value, `${path}/value`);
    }
    if (engine === undefined || construct === undefined) return undefined;
    const t: TableTemplate = { engine, construct };
    if (attribute !== undefined) t.attribute = attribute;
    if (value !== undefined) t.value = value;
    return t;
  }

  step(v: unknown, path: string, names: Map<string, string>): MatchStep | undefined {
    if (!this.keys(v, path, STEP_KEYS)) return undefined;
    if (Object.keys(v).length === 0) {
      this.add(path, 'bad-value', 'a step needs at least one key');
      return undefined;
    }
    const step: MatchStep = {};
    if (v.call !== undefined) step.call = this.call(v.call, `${path}/call`);
    const argIs = this.oneOf(v['arg-is'], `${path}/arg-is`, ARG_IS);
    if (argIs !== undefined) step.argIs = argIs;
    const literals = this.stringList(v['arg-literal-in'], `${path}/arg-literal-in`);
    if (literals !== undefined) step.argLiteralIn = literals;
    const role = this.oneOf(v.role, `${path}/role`, ROLES);
    if (role !== undefined) step.role = role;
    const on = this.bool(v.on, `${path}/on`);
    if (on !== undefined) step.on = on;
    if (v.name !== undefined) {
      const name = this.string(v.name, `${path}/name`);
      if (name !== undefined) {
        if (names.has(name)) this.add(`${path}/name`, 'duplicate-id', `step name "${name}" already used at ${names.get(name)}`);
        else names.set(name, path);
        step.name = name;
      }
    }
    if (v.order !== undefined) {
      if (Array.isArray(v.order) && v.order.length === 2 && v.order.every(isNonEmptyString)) {
        step.order = [v.order[0] as string, v.order[1] as string];
      } else {
        this.add(`${path}/order`, 'bad-value', 'expected [a, b], two step names');
      }
    }
    if (v.template !== undefined) step.template = this.template(v.template, `${path}/template`);
    if (v['sink-removed'] !== undefined) {
      if (v['sink-removed'] === true) step.sinkRemoved = true;
      else this.add(`${path}/sink-removed`, 'bad-value', 'sink-removed can only be true');
    }
    if (v.missing !== undefined) step.missing = this.step(v.missing, `${path}/missing`, names);
    for (const q of ['any', 'all'] as const) {
      if (v[q] === undefined) continue;
      const list = v[q];
      if (!Array.isArray(list) || list.length === 0) {
        this.add(`${path}/${q}`, 'bad-value', `${q} must be a non-empty list of steps`);
        continue;
      }
      const children = list.map((s, i) => this.step(s, `${path}/${q}/${i}`, names));
      step[q] = children.filter((s): s is MatchStep => s !== undefined);
    }
    return step;
  }
}

function collectOrders(step: MatchStep | undefined, path: string, out: { order: [string, string]; path: string }[]): void {
  if (!step) return;
  if (step.order) out.push({ order: step.order, path: `${path}/order` });
  if (step.missing) collectOrders(step.missing, `${path}/missing`, out);
  for (const q of ['any', 'all'] as const) step[q]?.forEach((s, i) => collectOrders(s, `${path}/${q}/${i}`, out));
}

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Parse and validate a `safe-construct-table@0.1`.
 *
 * `input` is the table's bytes (or its text, encoded UTF-8). The digest is
 * `sha256:<hex>` over exactly those bytes and is returned on refusal too, so a
 * caller can say which table was refused.
 */
export function loadSafeConstructTable(input: Uint8Array | string): LoadTableResult {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const digest = sha256Digest(bytes);
  const refuse = (problems: TableProblem[], format: string | null = null): LoadTableResult => ({ ok: false, digest, format, problems });

  const text = typeof input === 'string' ? input : decodeUtf8(bytes);
  if (text === null) return refuse([{ path: '', code: 'parse-error', message: 'not valid UTF-8' }]);

  const docs = parseAllDocuments(text, { uniqueKeys: true });
  if (!Array.isArray(docs)) return refuse([{ path: '', code: 'parse-error', message: 'empty document' }]);
  if (docs.length !== 1) return refuse([{ path: '', code: 'parse-error', message: `expected one YAML document, found ${docs.length}` }]);
  const doc = docs[0];
  if (doc.errors.length > 0) {
    return refuse(doc.errors.map(e => ({ path: '', code: 'parse-error' as const, message: e.message })));
  }
  const root: unknown = doc.toJS();

  const c = new Checker();
  if (!isMap(root)) return refuse([{ path: '', code: 'bad-value', message: 'the table must be a mapping' }]);
  const format = typeof root.format === 'string' ? root.format : null;
  if (format !== SAFE_CONSTRUCT_TABLE_FORMAT) {
    return refuse([{ path: '/format', code: 'unknown-format', message: `expected format "${SAFE_CONSTRUCT_TABLE_FORMAT}"; got ${JSON.stringify(root.format ?? null)}` }], format);
  }

  c.keys(root, '', TOP_KEYS, TOP_KEYS);
  const checkSet = c.string(root['check-set'], '/check-set');
  let cwe: number | undefined;
  if (root.cwe !== undefined) {
    if (typeof root.cwe === 'number' && Number.isInteger(root.cwe) && root.cwe > 0) cwe = root.cwe;
    else c.add('/cwe', 'bad-value', 'expected a positive integer');
  }
  const cweListVersion = c.string(root['cwe-list-version'], '/cwe-list-version');
  const language = c.string(root.language, '/language');
  const version = c.string(root.version, '/version');
  const settles = c.string(root.settles, '/settles');

  // sources
  const sources: Record<string, TableSource> = {};
  if (root.sources !== undefined) {
    if (!isMap(root.sources)) {
      c.add('/sources', 'bad-value', 'expected a mapping of id to citation');
    } else {
      for (const [id, s] of Object.entries(root.sources)) {
        const p = `/sources/${id}`;
        if (!c.keys(s, p, SOURCE_KEYS, SOURCE_REQUIRED)) continue;
        const fields: Partial<Record<string, string>> = {};
        for (const k of SOURCE_KEYS) {
          const val = c.string(s[k], `${p}/${k}`);
          if (val !== undefined) fields[k] = val;
        }
        if (SOURCE_REQUIRED.every(k => fields[k] !== undefined)) {
          const src: TableSource = {
            kind: fields.kind as string,
            publisher: fields.publisher as string,
            title: fields.title as string,
            url: fields.url as string,
            fetched: fields.fetched as string,
            quote: fields.quote as string,
          };
          if (fields.via !== undefined) src.via = fields.via;
          sources[id] = src;
        }
      }
    }
  }

  // sinks
  const sinks: TableSink[] = [];
  const sinkIds = new Set<string>();
  if (root.sinks !== undefined) {
    if (!Array.isArray(root.sinks)) {
      c.add('/sinks', 'bad-value', 'expected a list of sinks');
    } else {
      root.sinks.forEach((s: unknown, i: number) => {
        const p = `/sinks/${i}`;
        if (!c.keys(s, p, SINK_KEYS, ['id'])) return;
        const id = c.string(s.id, `${p}/id`);
        if (id !== undefined) {
          if (sinkIds.has(id)) c.add(`${p}/id`, 'duplicate-id', `duplicate sink id "${id}"`);
          sinkIds.add(id);
        }
        if ((s.call === undefined) === (s.template === undefined)) {
          c.add(p, 'bad-value', 'a sink has exactly one of call or template');
        }
        const call = s.call !== undefined ? c.call(s.call, `${p}/call`) : undefined;
        const template = s.template !== undefined ? c.template(s.template, `${p}/template`) : undefined;
        const note = c.string(s.note, `${p}/note`);
        if (id === undefined) return;
        const sink: TableSink = { id };
        if (call) sink.call = call;
        if (template) sink.template = template;
        if (note !== undefined) sink.note = note;
        sinks.push(sink);
      });
    }
  }

  // constructs
  const constructs: ConstructRow[] = [];
  const rowIds = new Set<string>();
  if (root.constructs !== undefined) {
    if (!Array.isArray(root.constructs)) {
      c.add('/constructs', 'bad-value', 'expected a list of rows');
    } else {
      root.constructs.forEach((r: unknown, i: number) => {
        const p = `/constructs/${i}`;
        if (!c.keys(r, p, ROW_KEYS, ROW_REQUIRED)) return;
        const id = c.string(r.id, `${p}/id`);
        if (id !== undefined) {
          if (rowIds.has(id)) c.add(`${p}/id`, 'duplicate-id', `duplicate row id "${id}"`);
          rowIds.add(id);
        }
        const cls = c.oneOf(r.class, `${p}/class`, CLASSES);
        const remedyClass = c.string(r['remedy-class'], `${p}/remedy-class`);
        let appliesTo: string[] | undefined;
        if (r['applies-to'] !== undefined) {
          if (!isStringList(r['applies-to']) || r['applies-to'].length === 0) {
            c.add(`${p}/applies-to`, 'bad-value', 'expected a non-empty list of sink ids');
          } else {
            appliesTo = r['applies-to'];
            appliesTo.forEach((a, j) => {
              if (!sinkIds.has(a)) c.add(`${p}/applies-to/${j}`, 'dangling-ref', `no sink "${a}" in this table`);
            });
          }
        }
        const context = c.string(r.context, `${p}/context`);
        const names = new Map<string, string>();
        const match = r.match !== undefined ? c.step(r.match, `${p}/match`, names) : undefined;
        const orders: { order: [string, string]; path: string }[] = [];
        collectOrders(match, `${p}/match`, orders);
        for (const o of orders) {
          for (const n of o.order) {
            if (!names.has(n)) c.add(o.path, 'dangling-ref', `order names "${n}", which no step of this row defines`);
          }
        }
        const level = c.oneOf(r.level, `${p}/level`, LEVELS);
        const basis = c.oneOf(r.basis, `${p}/basis`, BASES);
        let rowSources: string[] | undefined;
        if (r.sources !== undefined) {
          if (!isStringList(r.sources) || r.sources.length === 0) {
            c.add(`${p}/sources`, 'bad-value', 'expected a non-empty list of source ids');
          } else {
            rowSources = r.sources;
            rowSources.forEach((s, j) => {
              if (isMap(root.sources) && root.sources[s] === undefined) {
                c.add(`${p}/sources/${j}`, 'dangling-ref', `no source "${s}" in this table`);
              }
            });
          }
        }
        const residual = c.string(r.residual, `${p}/residual`);
        const note = c.string(r.note, `${p}/note`);
        const retired = c.string(r.retired, `${p}/retired`);
        if (
          id === undefined || cls === undefined || remedyClass === undefined || appliesTo === undefined ||
          match === undefined || level === undefined || basis === undefined || rowSources === undefined
        ) return;
        const row: ConstructRow = { id, class: cls, remedyClass, appliesTo, match, level, basis, sources: rowSources };
        if (context !== undefined) row.context = context;
        if (residual !== undefined) row.residual = residual;
        if (note !== undefined) row.note = note;
        if (retired !== undefined) row.retired = retired;
        constructs.push(row);
      });
    }
  }

  if (c.problems.length > 0) return refuse(c.problems, format);
  return {
    ok: true,
    digest,
    table: {
      format: SAFE_CONSTRUCT_TABLE_FORMAT,
      checkSet: checkSet as string,
      cwe: cwe as number,
      cweListVersion: cweListVersion as string,
      language: language as string,
      version: version as string,
      settles: settles as string,
      sources,
      sinks,
      constructs,
    },
  };
}
