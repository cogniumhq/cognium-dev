/**
 * Navigation queries — callers and callees, each answer carrying how it was
 * reached and each non-answer carrying why.
 *
 * This is an **additive** surface. `CrossFileResolver.resolveCall` and
 * `.findCallers` are untouched: the SAST passes and the taint corpora depend on
 * their exact behaviour, and a change there ships behind the corpora gates, not
 * with a navigation feature. So this module builds its own index from the same
 * IR and answers its own questions.
 *
 * What it does that `resolveCall` does not, and why each one is here:
 *
 *   - **A `record` receiver.** `resolveCall` cannot see a record because the
 *     default extraction emits no type for one. Asking `analyze` for
 *     `navigationTypes` fixes that upstream; this index then treats a record
 *     like any other class.
 *   - **A chained receiver.** `failed(this).feedback(x).output(y)` arrives with
 *     the receiver as an expression string. The chain is walked left to right,
 *     typing each step from the previous step's declared return type.
 *   - **A constructor.** `new Widget()` arrives as a call named `Widget` with
 *     no receiver. It is bound to `app.Widget.<init>`.
 *   - **A nested type's static import.** `import static app.Outer.Inner.make`
 *     names `app.Outer.Inner.make`, which only matches a symbol table that
 *     kept the nesting — hence `TypeInfo.enclosing_type`.
 *
 * Those four are not a wish list: they are every shape found by auditing the
 * 8,015 call sites `resolveCall` leaves unanswered in a 405-file Java
 * repository, of which 7,246 are correctly unanswered (the target is outside
 * the tree) and 455 are these.
 *
 * What it deliberately does **not** do: invent a receiver type. Where no type
 * is known the answer is `inferred` or there is no answer, and `inferred` is a
 * permanent floor — see `Tier`.
 */

import type { CircleIR, CallInfo, TypeInfo, SupportedLanguage } from '../types/index.js';
import type {
  AnswerEntry,
  CallSite,
  NavigationAnswer,
  Query,
  QueryKind,
  QueryOptions,
  Scope,
  Tier,
  UnresolvedEntry,
  UnresolvedReason,
} from './types.js';

/** One file's input to the index. `ir` must come from `analyze` with `navigationTypes`. */
export interface NavigationFile {
  path: string;
  language: SupportedLanguage;
  ir: CircleIR;
  /** The file's text. Only used to put the source line on a site. */
  source?: string;
  /**
   * A content hash for this file. Supplied, or derived from `source`. With
   * `BuildOptions.cache` set, a file whose hash is unchanged is not re-indexed.
   */
  contentHash?: string;
}

export interface BuildOptions {
  /**
   * Reuse per-file index records across builds, keyed by content hash and by
   * this module's own version marker. Minimal by design — enough to keep a
   * trial's answers fresh between edits; the incremental workspace index is a
   * separate piece of work.
   */
  cache?: boolean;
  /** Paths left out of the index, each with the reason, reported in `scope.excluded`. */
  excluded?: Array<{ pattern: string; reason: string }>;
  /** Wall time the caller spent parsing, so `timing.parseMs` is not a guess. */
  parseMs?: number;
}

/**
 * What is known about a receiver's static type.
 *
 * The distinction between `foreign` and nothing at all is the whole of the
 * `exact` promise. A receiver whose type is known to be something we do not
 * hold cannot be calling our method of that name, so the honest output is no
 * answer and a scope reason. A receiver with no type at all is a different
 * situation, and the floor tier exists for it.
 */
/** What `bind` decides: everything in an answer that is not about the site. */
type BoundTarget = Omit<AnswerEntry, 'site' | 'methodName'>;

type ReceiverType =
  | { kind: 'project'; fqn: string; evidence: string }
  | { kind: 'foreign'; name: string; evidence: string };

interface TypeRecord {
  fqn: string;
  simpleName: string;
  kind: TypeInfo['kind'];
  isRecord: boolean;
  file: string;
  /** Simple names, as written in the source. */
  superNames: string[];
  annotations: string[];
  fieldNames: string[];
  /** Field names carrying a field-level `@Getter` / `@Setter`. */
  getterFields: string[];
  setterFields: string[];
  methods: Map<string, { returnType: string | null; startLine: number; endLine: number }>;
  startLine: number;
  endLine: number;
}

interface FileRecord {
  path: string;
  language: SupportedLanguage;
  pkg: string;
  parseOk: boolean;
  /** Simple name → FQN, from this file's imports. */
  imports: Map<string, string>;
  /** Statically imported member name → the FQN of the type that owns it. */
  staticImports: Map<string, string>;
  /** Wildcard static imports, as owner FQNs. */
  staticWildcards: string[];
  types: TypeRecord[];
  calls: CallInfo[];
  lines?: string[];
}

const REFLECTIVE_TYPES = new Set([
  'Class', 'Method', 'Field', 'Constructor', 'AccessibleObject',
  'MethodHandle', 'MethodHandles', 'Proxy', 'InvocationHandler', 'ClassLoader',
]);
const REFLECTIVE_METHODS = new Set([
  'forName', 'setAccessible', 'getDeclaredMethod', 'getDeclaredField',
  'getDeclaredConstructor', 'newProxyInstance', 'getAnnotation',
  'getAnnotationsByType', 'isAnnotationPresent', 'getGenericReturnType',
]);
const LOMBOK_ACCESSOR = new Set(['Getter', 'Setter', 'Data', 'Value']);
const LOMBOK_BUILDER = new Set(['Builder', 'SuperBuilder']);

/** Bumped when the shape of a cached per-file record changes. */
const CACHE_VERSION = 'nav-1';
const fileCache = new Map<string, FileRecord>();

export function buildNavigationIndex(
  files: NavigationFile[],
  options: BuildOptions = {},
): NavigationIndex {
  return new NavigationIndex(files, options);
}

export class NavigationIndex {
  private readonly files = new Map<string, FileRecord>();
  private readonly typesByFqn = new Map<string, TypeRecord>();
  private readonly typesBySimpleName = new Map<string, TypeRecord[]>();
  /** Every method name declared anywhere in the tree — "is the target in scope at all?" */
  private readonly declaredNames = new Set<string>();
  /** Package prefixes of the indexed files, longest first. */
  private readonly projectPackages: string[] = [];
  private readonly scope: Scope;
  private readonly indexMs: number;
  private readonly parseMs: number;
  /** Direct subtypes, by supertype FQN. */
  private readonly subtypes = new Map<string, Set<string>>();

  constructor(input: NavigationFile[], options: BuildOptions) {
    const t0 = now();
    for (const f of input) {
      const key = f.contentHash ?? (f.source !== undefined ? cheapHash(f.source) : undefined);
      const cacheKey = key ? `${CACHE_VERSION}:${f.path}:${key}` : undefined;
      let rec = options.cache && cacheKey ? fileCache.get(cacheKey) : undefined;
      if (!rec) {
        rec = buildFileRecord(f);
        if (options.cache && cacheKey) fileCache.set(cacheKey, rec);
      }
      this.files.set(f.path, rec);
    }

    const pkgs = new Set<string>();
    for (const rec of this.files.values()) {
      if (rec.pkg) pkgs.add(rec.pkg);
      for (const t of rec.types) {
        this.typesByFqn.set(t.fqn, t);
        push(this.typesBySimpleName, t.simpleName, t);
        for (const m of t.methods.keys()) this.declaredNames.add(m);
      }
    }
    // The shortest distinct package prefixes, so `app.a` and `app.b` both
    // count as inside the tree without listing every leaf.
    this.projectPackages = shortestPrefixes([...pkgs]);

    // Subtype edges, from simple names resolved in the declaring file.
    for (const rec of this.files.values()) {
      for (const t of rec.types) {
        for (const sup of t.superNames) {
          const supFqn = this.resolveTypeName(sup, rec) ?? sup;
          push2(this.subtypes, supFqn, t.fqn);
        }
      }
    }

    const languages = [...new Set([...this.files.values()].map(f => f.language))].sort();
    this.scope = {
      searched: { files: this.files.size, languages },
      excluded: options.excluded ?? [],
    };
    this.indexMs = now() - t0;
    this.parseMs = options.parseMs ?? 0;
  }

  // ---------------------------------------------------------------- queries

  /**
   * Every call site that calls `symbol`, with how each was bound, plus every
   * site that calls something of that *name* and could not be bound, with why.
   *
   * The second list is the point. A name-only search on a 405-file repository
   * reported 147 callers of one method where the right answer was 0 `exact`,
   * 69 unverified and 78 contradicted by the resolver's own receiver type. Here
   * the 78 do not appear as answers at all, and the 69 arrive labelled.
   */
  resolveCallers(query: Query, opts: QueryOptions = {}): NavigationAnswer {
    const t0 = now();
    const symbol = this.querySymbol(query, 'callers');
    const answers: AnswerEntry[] = [];
    const unresolved: UnresolvedEntry[] = [];

    if (symbol === undefined) {
      return this.finish('callers', query, answers, unresolved, t0, opts);
    }
    const wantedName = lastSegment(symbol);

    for (const rec of this.files.values()) {
      for (const call of rec.calls) {
        if (!this.nameCouldMatch(call, wantedName, symbol, rec)) continue;
        const bound = this.bind(call, rec);
        if (bound && bound.target === symbol) {
          answers.push({ ...bound, methodName: call.method_name, site: this.siteOf(call, rec) });
        } else if (!bound) {
          unresolved.push({
            site: this.siteOf(call, rec),
            reason: this.reasonFor(call, rec),
            methodName: call.method_name,
          });
        }
        // A site bound to a different target is neither: it is answered, elsewhere.
      }
    }
    return this.finish('callers', query, answers, unresolved, t0, opts);
  }

  /** Every call made from inside `symbol`'s body, bound the same way. */
  resolveCallees(query: Query, opts: QueryOptions = {}): NavigationAnswer {
    const t0 = now();
    const symbol = this.querySymbol(query, 'callees');
    const answers: AnswerEntry[] = [];
    const unresolved: UnresolvedEntry[] = [];

    if (symbol === undefined) {
      return this.finish('callees', query, answers, unresolved, t0, opts);
    }
    const owner = this.typesByFqn.get(stripLast(symbol));
    const method = owner?.methods.get(lastSegment(symbol));
    if (!owner || !method) {
      return this.finish('callees', query, answers, unresolved, t0, opts);
    }
    const rec = this.files.get(owner.file);
    if (!rec) return this.finish('callees', query, answers, unresolved, t0, opts);

    for (const call of rec.calls) {
      const line = call.location.line;
      if (line < method.startLine || line > method.endLine) continue;
      const bound = this.bind(call, rec);
      if (bound) answers.push({ ...bound, methodName: call.method_name, site: this.siteOf(call, rec) });
      else {
        unresolved.push({
          site: this.siteOf(call, rec),
          reason: this.reasonFor(call, rec),
          methodName: call.method_name,
        });
      }
    }
    return this.finish('callees', query, answers, unresolved, t0, opts);
  }

  /**
   * The symbol a call site names, so a caller holding a line of code can ask
   * the same question as a caller holding a name.
   *
   * Keyed on `(file, line, methodName)` and **not** on a column: a chained
   * expression reports several calls at one line and column, so a column
   * cannot address one of them. The method name is what completes the key.
   *
   * For `callers` the symbol is the call's own target — "who else calls what
   * this line calls". For `callees` it is the method whose body holds the
   * line — "what does the method I am looking at call". Returns nothing when
   * the site names no call, when the call cannot be bound to a target, or
   * when the name is written twice on one line, which the key cannot separate.
   */
  symbolAt(
    file: string,
    line: number,
    methodName: string,
    kind: QueryKind,
  ): string | undefined {
    const rec = this.files.get(file);
    if (!rec) return undefined;

    if (kind === 'callees') {
      const t = this.enclosingTypeAt(rec, line);
      if (!t) return undefined;
      for (const [name, m] of t.methods) {
        if (line >= m.startLine && line <= m.endLine) return `${t.fqn}.${name}`;
      }
      return undefined;
    }

    const at = rec.calls.filter(
      (c) => c.location.line === line && c.method_name === methodName,
    );
    // The same name twice on one line is beyond this key, and picking one of
    // them would be a guess presented as an answer.
    if (at.length !== 1) return undefined;
    return this.bind(at[0], rec)?.target;
  }

  // ------------------------------------------------------------ the binding

  /**
   * Bind one call site to a target, or to nothing.
   *
   * The order matters and is the whole contract: a receiver type is sought
   * first, and only when none can be had does a name-only bind happen, which
   * is labelled `inferred` and never anything better.
   */
  private bind(call: CallInfo, rec: FileRecord): BoundTarget | undefined {
    // A constructor arrives as a call named after the type, with no receiver.
    const ctor = this.asConstructor(call, rec);
    if (ctor) return ctor;

    const recv = this.receiverTypeOf(call, rec);

    // The receiver's type is known and is not ours. Binding by name here is
    // precisely the contradiction the contract forbids: on a 405-file
    // repository, 78 of 147 name-only "callers" of one method had a receiver
    // whose own declared type could not have that method. A known foreign type
    // is an answer about scope, not a weak answer about a target.
    if (recv?.kind === 'foreign') return undefined;

    if (recv?.kind === 'project') {
      const hit = this.lookupThroughHierarchy(recv.fqn, call.method_name);
      if (hit) {
        const impls = this.implementorsWith(hit.owner.fqn, call.method_name);
        // Dispatch is open when the declaring type has subtypes that override
        // it, or when it carries no body of its own to run.
        if (impls.length > 1 || (hit.owner.kind === 'interface' && impls.length >= 1)) {
          return {
            target: `${hit.owner.fqn}.${call.method_name}`,
            tier: 'polymorphic',
            candidates: impls.map(t => `${t}.${call.method_name}`),
            evidence: `${recv.evidence}; ${call.method_name} is declared on ${hit.owner.kind} ${hit.owner.fqn} with ${impls.length} implementor(s) in the searched tree`,
          };
        }
        return {
          target: `${hit.owner.fqn}.${call.method_name}`,
          tier: 'exact',
          evidence: `${recv.evidence}; ${call.method_name} is the unique method of that name on ${hit.owner.fqn}`,
        };
      }
      // The receiver's type is known and does not have this method. Binding by
      // name here would be the contradiction the audit found 78 of, so no.
      return undefined;
    }

    // A statically imported member names its owner outright.
    const owner = this.staticOwnerFor(call, rec);
    if (owner) {
      const hit = this.lookupThroughHierarchy(owner.fqn, call.method_name);
      if (hit) {
        return {
          target: `${hit.owner.fqn}.${call.method_name}`,
          tier: 'exact',
          evidence: `${owner.evidence}; ${call.method_name} is declared on ${hit.owner.fqn}`,
        };
      }
    }

    // No receiver at all: an unqualified call is `this` or the enclosing type's
    // own static method. The enclosing type is known exactly, so this is not a
    // guess.
    if (call.receiver === null && !call.receiver_type) {
      const encl = this.enclosingTypeOf(call, rec);
      if (encl) {
        const hit = this.lookupThroughHierarchy(encl.fqn, call.method_name);
        if (hit) {
          return {
            target: `${hit.owner.fqn}.${call.method_name}`,
            tier: 'exact',
            evidence: `unqualified call inside ${encl.fqn}; ${call.method_name} is declared on ${hit.owner.fqn}`,
          };
        }
      }
    }

    // Nothing typed the receiver. A name-only bind is the floor, and only when
    // the name is unambiguous in the tree — a name owned by several types is
    // not evidence of anything.
    const byName = this.uniqueByName(call.method_name);
    if (byName) {
      return {
        target: `${byName.fqn}.${call.method_name}`,
        tier: 'inferred',
        evidence: `bound by method name alone — no receiver type was available; ${call.method_name} is declared exactly once in the searched tree, on ${byName.fqn}`,
      };
    }
    return undefined;
  }

  /** `new Widget()` → `app.Widget.<init>`. */
  private asConstructor(call: CallInfo, rec: FileRecord): BoundTarget | undefined {
    const looksCtor =
      call.is_constructor === true ||
      (call.receiver === null &&
        !!call.receiver_type &&
        call.receiver_type === call.method_name &&
        /^[A-Z]/.test(call.method_name));
    if (!looksCtor) return undefined;
    const t = this.resolveTypeRecord(call.receiver_type ?? call.method_name, rec);
    if (!t) return undefined;
    return {
      target: `${t.fqn}.<init>`,
      tier: 'exact',
      evidence: `object creation of ${t.fqn}, declared at ${t.file}:${t.startLine}`,
    };
  }

  /**
   * The receiver's static type, where it can be had without inventing one.
   *
   * Four sources, in order of how much they are trusted: the extractor's own
   * fully-qualified answer, its simple-name answer resolved through this file's
   * imports, a chain of calls whose declared return types can be walked, and a
   * bare type name used as a static receiver.
   */
  private receiverTypeOf(call: CallInfo, rec: FileRecord): ReceiverType | undefined {
    if (call.is_constructor) return undefined;

    if (call.receiver_type_fqn) {
      const t = this.typesByFqn.get(call.receiver_type_fqn);
      if (t) {
        return { kind: 'project', fqn: t.fqn, evidence: `receiver type ${t.fqn} from the extractor` };
      }
      return {
        kind: 'foreign',
        name: call.receiver_type_fqn,
        evidence: `receiver type ${call.receiver_type_fqn}, which is not declared in the searched tree`,
      };
    }

    if (call.receiver_type) {
      const t = this.resolveTypeRecord(call.receiver_type, rec);
      if (t) {
        return {
          kind: 'project',
          fqn: t.fqn,
          evidence: `receiver declared as ${call.receiver_type}, resolved to ${t.fqn}`,
        };
      }
      // `var` is the extractor saying it read an inferred declaration, not that
      // it knows the type — so it is no type at all, not a foreign one.
      if (call.receiver_type === 'var') return undefined;
      return {
        kind: 'foreign',
        name: call.receiver_type,
        evidence: `receiver declared as ${call.receiver_type}, a type outside the searched tree`,
      };
    }

    return this.typeOfExpression(call.receiver, rec, 0);
  }

  /**
   * The type a receiver *expression* evaluates to.
   *
   * `Builder.of().step("a")` is typed by resolving `Builder`, then taking
   * `of`'s declared return type, then `step`'s. A step whose return type is
   * unknown ends the walk and the whole expression is untyped — a half-walked
   * chain is not a type.
   */
  private typeOfExpression(
    expr: string | null | undefined,
    rec: FileRecord,
    depth: number,
  ): ReceiverType | undefined {
    if (!expr || depth > 8) return undefined;
    const text = expr.replace(/\s+/g, ' ').trim();
    const chain = splitCallChain(text);
    if (!chain) return undefined;

    let current: TypeRecord | undefined;
    let evidence = '';

    // The root is a type name used statically, `this`, or a call on the
    // enclosing type (a statically imported factory, or its own method).
    const root = chain.root;
    if (root.kind === 'type') {
      current = this.resolveTypeRecord(root.name, rec);
      if (!current) return undefined;
      evidence = `chain rooted at type ${current.fqn}`;
    } else if (root.kind === 'this') {
      current = this.enclosingTypeAt(rec, chain.steps[0]?.line ?? 0) ?? rec.types[0];
      if (!current) return undefined;
      evidence = `chain rooted at this (${current.fqn})`;
    } else {
      // A bare call: `failed(this).feedback(x)`. Its owner is a static import
      // or the enclosing type.
      const ownerFqn =
        rec.staticImports.get(root.name) ??
        rec.staticWildcards.find(w => this.typesByFqn.get(w)?.methods.has(root.name)) ??
        rec.types.find(t => t.methods.has(root.name))?.fqn;
      const owner = ownerFqn ? this.typesByFqn.get(ownerFqn) : undefined;
      const m = owner?.methods.get(root.name);
      if (!owner || !m || !m.returnType) return undefined;
      current = this.resolveTypeRecord(m.returnType, rec);
      if (!current) return undefined;
      evidence = `chain rooted at ${owner.fqn}.${root.name}, which returns ${m.returnType}`;
    }

    for (const step of chain.steps) {
      const hit = this.lookupThroughHierarchy(current.fqn, step.name);
      const m = hit?.owner.methods.get(step.name);
      if (!m || !m.returnType) return undefined;
      const next = this.resolveTypeRecord(m.returnType, rec);
      if (!next) return undefined;
      evidence += ` → ${step.name}() returns ${m.returnType}`;
      current = next;
    }
    return { kind: 'project', fqn: current.fqn, evidence };
  }

  /** The owner named by a static import of this call's method. */
  private staticOwnerFor(
    call: CallInfo,
    rec: FileRecord,
  ): { fqn: string; evidence: string } | undefined {
    if (call.receiver !== null) return undefined;
    const direct = rec.staticImports.get(call.method_name);
    if (direct && this.typesByFqn.has(direct)) {
      return { fqn: direct, evidence: `statically imported from ${direct}` };
    }
    for (const w of rec.staticWildcards) {
      if (this.typesByFqn.get(w)?.methods.has(call.method_name)) {
        return { fqn: w, evidence: `statically imported from ${w}.*` };
      }
    }
    return undefined;
  }

  private enclosingTypeOf(call: CallInfo, rec: FileRecord): TypeRecord | undefined {
    return this.enclosingTypeAt(rec, call.location.line);
  }

  /** The innermost declared type whose line range holds `line`. */
  private enclosingTypeAt(rec: FileRecord, line: number): TypeRecord | undefined {
    let best: TypeRecord | undefined;
    for (const t of rec.types) {
      if (line < t.startLine || line > t.endLine) continue;
      if (!best || t.startLine > best.startLine) best = t;
    }
    return best ?? rec.types[0];
  }

  /** Find `method` on `fqn` or on a supertype of it, inside the tree. */
  private lookupThroughHierarchy(
    fqn: string,
    method: string,
    seen = new Set<string>(),
  ): { owner: TypeRecord } | undefined {
    if (seen.has(fqn)) return undefined;
    seen.add(fqn);
    const t = this.typesByFqn.get(fqn);
    if (!t) return undefined;
    if (t.methods.has(method)) return { owner: t };
    const rec = this.files.get(t.file);
    for (const sup of t.superNames) {
      const supFqn = rec ? this.resolveTypeName(sup, rec) : undefined;
      if (!supFqn) continue;
      const hit = this.lookupThroughHierarchy(supFqn, method, seen);
      if (hit) return hit;
    }
    return undefined;
  }

  /** Types in the tree that declare `method` and are `fqn` or below it. */
  private implementorsWith(fqn: string, method: string): string[] {
    const out: string[] = [];
    const walk = (f: string, seen: Set<string>): void => {
      if (seen.has(f)) return;
      seen.add(f);
      const t = this.typesByFqn.get(f);
      if (t && t.methods.has(method) && t.kind !== 'interface') out.push(f);
      for (const sub of this.subtypes.get(f) ?? []) walk(sub, seen);
    };
    walk(fqn, new Set());
    return out;
  }

  /** The one type in the tree declaring `name`, or nothing if it is not unique. */
  private uniqueByName(name: string): TypeRecord | undefined {
    const owners: TypeRecord[] = [];
    for (const t of this.typesByFqn.values()) {
      if (t.methods.has(name)) owners.push(t);
      if (owners.length > 1) return undefined;
    }
    return owners[0];
  }

  /** A simple or qualified type name, resolved from one file's point of view. */
  private resolveTypeRecord(name: string, rec: FileRecord): TypeRecord | undefined {
    const fqn = this.resolveTypeName(name, rec);
    return fqn ? this.typesByFqn.get(fqn) : undefined;
  }

  private resolveTypeName(name: string, rec: FileRecord): string | undefined {
    const bare = name.replace(/<.*>$/, '').replace(/\[\]$/, '').trim();
    if (!bare) return undefined;
    if (this.typesByFqn.has(bare)) return bare;
    const imported = rec.imports.get(bare);
    if (imported && this.typesByFqn.has(imported)) return imported;
    // Same package, including a nested type of a type in this file.
    const samePkg = rec.pkg ? `${rec.pkg}.${bare}` : bare;
    if (this.typesByFqn.has(samePkg)) return samePkg;
    for (const t of rec.types) {
      const nested = `${t.fqn}.${bare}`;
      if (this.typesByFqn.has(nested)) return nested;
    }
    // A unique simple name anywhere in the tree. Ambiguity resolves to nothing
    // rather than to a guess.
    const byName = this.typesBySimpleName.get(bare);
    if (byName && byName.length === 1) return byName[0].fqn;
    return undefined;
  }

  // ------------------------------------------------------------- the reason

  /**
   * Why a site in range produced no answer.
   *
   * Every branch rests on something read from the source, not on a default.
   * `unknown` is the honest end of the list: the target is in the tree and this
   * index failed to bind it, which is a different claim from the other five and
   * is reported as its own share.
   */
  private reasonFor(call: CallInfo, rec: FileRecord): UnresolvedReason {
    if (!rec.parseOk) return 'parse-error';
    if (!this.parses(rec.language)) return 'unsupported-language';

    if (
      REFLECTIVE_TYPES.has(call.receiver_type ?? '') ||
      REFLECTIVE_METHODS.has(call.method_name) ||
      /\bgetClass\s*\(\s*\)\s*$|\.class$|Class\.forName/.test(call.receiver ?? '')
    ) {
      return 'dynamic';
    }

    // A member that only exists after annotation processing. The receiver's
    // type is ours, the member is not written anywhere in it, and an
    // annotation on the type or the field would have generated it.
    const recvType =
      (call.receiver_type_fqn ? this.typesByFqn.get(call.receiver_type_fqn) : undefined) ??
      (call.receiver_type ? this.resolveTypeRecord(call.receiver_type, rec) : undefined) ??
      (call.receiver === null ? this.enclosingTypeOf(call, rec) : undefined);
    if (recvType && this.wouldBeGenerated(recvType, call.method_name)) return 'generated';
    if (call.receiver && this.builderChainWouldGenerate(call, rec)) return 'generated';

    // Outside the tree: the extractor gave a package that is not ours, or an
    // import does, or the name is declared in no file we indexed.
    const fqn = call.receiver_type_fqn;
    if (fqn && !this.isProjectFqn(fqn)) return 'external';
    if (call.receiver_type) {
      const imported = rec.imports.get(call.receiver_type);
      if (imported && !this.isProjectFqn(imported)) return 'external';
    }
    if (call.receiver === null) {
      const stat = rec.staticImports.get(call.method_name);
      if (stat && !this.isProjectFqn(stat)) return 'external';
    }
    if (!this.declaredNames.has(call.method_name)) return 'external';

    return 'unknown';
  }

  /** `@Getter`/`@Setter`/`@Data`/`@Builder` would add this member. */
  private wouldBeGenerated(t: TypeRecord, method: string): boolean {
    const seen = new Set<string>();
    const walk = (fqn: string): boolean => {
      if (seen.has(fqn)) return false;
      seen.add(fqn);
      const rt = this.typesByFqn.get(fqn);
      if (!rt) return false;
      if (rt.methods.has(method)) return false;
      const anns = new Set(rt.annotations);
      const lower = (s: string): string => s.charAt(0).toLowerCase() + s.slice(1);
      const any = (set: Set<string>): boolean => [...anns].some(a => set.has(a));
      if (any(LOMBOK_BUILDER) && (method === 'builder' || method === 'toBuilder')) return true;
      if (any(LOMBOK_ACCESSOR)) {
        if (/^get[A-Z]/.test(method) && rt.fieldNames.includes(lower(method.slice(3)))) return true;
        if (/^is[A-Z]/.test(method) && rt.fieldNames.includes(lower(method.slice(2)))) return true;
        if (/^set[A-Z]/.test(method) && rt.fieldNames.includes(lower(method.slice(3)))) return true;
      }
      if (/^get[A-Z]/.test(method) && rt.getterFields.includes(lower(method.slice(3)))) return true;
      if (/^is[A-Z]/.test(method) && rt.getterFields.includes(lower(method.slice(2)))) return true;
      if (/^set[A-Z]/.test(method) && rt.setterFields.includes(lower(method.slice(3)))) return true;
      if (anns.has('Slf4j') && ['info', 'warn', 'error', 'debug', 'trace'].includes(method)) return true;
      const frec = this.files.get(rt.file);
      for (const sup of rt.superNames) {
        const supFqn = frec ? this.resolveTypeName(sup, frec) : undefined;
        if (supFqn && walk(supFqn)) return true;
      }
      return false;
    };
    return walk(t.fqn);
  }

  /** `Email.builder().title(...)` — a builder setter named after a field. */
  private builderChainWouldGenerate(call: CallInfo, rec: FileRecord): boolean {
    const m = /^([A-Z]\w*)\s*\.\s*builder\s*\(/.exec((call.receiver ?? '').replace(/\s+/g, ' '));
    if (!m) return false;
    const t = this.resolveTypeRecord(m[1], rec);
    if (!t) return false;
    const builds = t.annotations.some(a => LOMBOK_BUILDER.has(a));
    return builds && t.fieldNames.includes(call.method_name);
  }

  private isProjectFqn(fqn: string): boolean {
    return this.projectPackages.some(p => fqn === p || fqn.startsWith(`${p}.`));
  }

  private parses(language: SupportedLanguage): boolean {
    return language === 'java';
  }

  // -------------------------------------------------------------- plumbing

  /** A site whose method name could be the one asked for. */
  private nameCouldMatch(
    call: CallInfo,
    wantedName: string,
    symbol: string,
    rec: FileRecord,
  ): boolean {
    if (wantedName === '<init>') {
      const typeFqn = stripLast(symbol);
      const t = this.typesByFqn.get(typeFqn);
      return !!t && (call.is_constructor === true || call.method_name === t.simpleName);
    }
    void rec;
    return call.method_name === wantedName;
  }

  private querySymbol(query: Query, kind: QueryKind): string | undefined {
    if (query.symbol) return query.symbol;
    if (!query.site) return undefined;
    // A site query on `callers` means "who calls the method this site calls";
    // on `callees` it means "what does the method holding this site call".
    const rec = this.files.get(query.site.file);
    if (!rec) return undefined;
    // A (line, col) triple can name several calls in a chained expression, so
    // a site query that does not say which method it means is ambiguous and
    // gets no answer rather than an arbitrary one.
    const at = rec.calls.filter(
      c => c.location.line === query.site!.line && c.location.column === query.site!.col,
    );
    const call = at.length === 1 ? at[0] : undefined;
    if (kind === 'callers') {
      if (!call) return undefined;
      return this.bind(call, rec)?.target;
    }
    const t = this.enclosingTypeAt(rec, query.site.line);
    if (!t) return undefined;
    for (const [name, m] of t.methods) {
      if (query.site.line >= m.startLine && query.site.line <= m.endLine) {
        return `${t.fqn}.${name}`;
      }
    }
    return undefined;
  }

  private siteOf(call: CallInfo, rec: FileRecord): CallSite {
    const site: CallSite = {
      file: rec.path,
      line: call.location.line,
      col: call.location.column,
      inMethod: call.in_method ?? null,
    };
    const text = rec.lines?.[call.location.line - 1];
    if (text !== undefined) site.text = text.trim();
    return site;
  }

  private finish(
    kind: QueryKind,
    query: Query,
    answers: AnswerEntry[],
    unresolved: UnresolvedEntry[],
    t0: number,
    opts: QueryOptions,
  ): NavigationAnswer {
    let kept = answers;
    if (opts.tiers) kept = kept.filter(a => opts.tiers!.includes(a.tier));
    kept = [...kept].sort(
      (a, b) => a.site.file.localeCompare(b.site.file) || a.site.line - b.site.line,
    );
    const total = kept.length;
    let truncated: NavigationAnswer['truncated'];
    if (opts.limit !== undefined && total > opts.limit) {
      kept = kept.slice(0, opts.limit);
      truncated = { returned: kept.length, total };
    }
    const out: NavigationAnswer = {
      query: { kind, ...(query.symbol ? { symbol: query.symbol } : { site: query.site }) },
      answers: kept,
      unresolved: [...unresolved].sort(
        (a, b) => a.site.file.localeCompare(b.site.file) || a.site.line - b.site.line,
      ),
      scope: this.scope,
      timing: {
        parseMs: round(this.parseMs),
        indexMs: round(this.indexMs),
        queryMs: round(now() - t0),
      },
    };
    if (truncated) out.truncated = truncated;
    return out;
  }
}

// ------------------------------------------------------------------ helpers

function buildFileRecord(f: NavigationFile): FileRecord {
  const pkg = f.ir.meta?.package ?? '';
  const imports = new Map<string, string>();
  const staticImports = new Map<string, string>();
  const staticWildcards: string[] = [];
  for (const imp of f.ir.imports ?? []) {
    const from = imp.from_package ?? '';
    const name = imp.imported_name ?? '';
    if (!from && !name) continue;
    if (imp.is_wildcard) {
      // `import static app.Outer.Inner.*` and `import app.pkg.*` are not
      // distinguished by the IR; treating the package as a static owner is
      // harmless, because an owner that is not a type in the tree never matches.
      staticWildcards.push(from);
      continue;
    }
    // A static import's `from_package` is the owning *type*, not a package —
    // `import static app.Outer.Inner.make` gives `app.Outer.Inner` / `make`.
    staticImports.set(name, from);
    imports.set(name, from ? `${from}.${name}` : name);
  }

  const types: TypeRecord[] = [];
  for (const t of f.ir.types ?? []) {
    const tpkg = t.package ?? pkg;
    const path = [tpkg, t.enclosing_type, t.name].filter(Boolean).join('.');
    const methods = new Map<string, { returnType: string | null; startLine: number; endLine: number }>();
    for (const m of t.methods ?? []) {
      // A later overload does not replace an earlier one's range; the widest
      // range wins, so a callee query over the method's body sees all of it.
      const prev = methods.get(m.name);
      methods.set(m.name, {
        returnType: m.return_type ?? prev?.returnType ?? null,
        startLine: prev ? Math.min(prev.startLine, m.start_line) : m.start_line,
        endLine: prev ? Math.max(prev.endLine, m.end_line) : m.end_line,
      });
    }
    types.push({
      fqn: path,
      simpleName: t.name,
      kind: t.kind,
      isRecord: t.is_record === true,
      file: f.path,
      superNames: [t.extends, ...(t.implements ?? [])].filter((x): x is string => !!x),
      annotations: (t.annotations ?? []).map(stripAnnotation),
      fieldNames: (t.fields ?? []).map(x => x.name),
      getterFields: lombokFields(f.source, 'Getter'),
      setterFields: lombokFields(f.source, 'Setter'),
      methods,
      startLine: t.start_line,
      endLine: t.end_line,
    });
  }

  return {
    path: f.path,
    language: f.language,
    pkg,
    parseOk: f.ir.parse_status ? f.ir.parse_status.success !== false : true,
    imports,
    staticImports,
    staticWildcards,
    types,
    calls: f.ir.calls ?? [],
    lines: f.source?.split('\n'),
  };
}

/** `@Getter` written on a field, which no extractor reports as an annotation. */
function lombokFields(source: string | undefined, kind: 'Getter' | 'Setter'): string[] {
  if (!source) return [];
  const re = new RegExp(`@${kind}(?:\\([^)]*\\))?[^;\\n]*?\\b(\\w+)\\s*(?:=|;)`, 'g');
  return [...new Set([...source.matchAll(re)].map(m => m[1]))];
}

function stripAnnotation(a: string): string {
  return a.replace(/^@/, '').replace(/\(.*$/, '').split('.').pop() ?? a;
}

/**
 * Split a receiver expression into a root and a list of `.name(...)` steps.
 *
 * Returns nothing for anything that is not a chain of calls on a nameable
 * root — an array index, a ternary, an arithmetic expression. Not typing an
 * expression is the correct outcome for all of those.
 */
function splitCallChain(
  text: string,
): { root: { kind: 'type' | 'this' | 'call'; name: string }; steps: Array<{ name: string; line: number }> } | null {
  // Walk the string, splitting on top-level dots only, so a dot inside an
  // argument list or a string literal does not end a step.
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let buf = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      buf += ch;
      if (ch === quote && text[i - 1] !== '\\') quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; buf += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '<') depth++;
    if (ch === ')' || ch === ']' || ch === '>') depth--;
    if (ch === '.' && depth === 0) { parts.push(buf); buf = ''; continue; }
    buf += ch;
  }
  parts.push(buf);
  if (parts.length === 0) return null;

  const head = parts[0].trim();
  let root: { kind: 'type' | 'this' | 'call'; name: string };
  if (head === 'this') root = { kind: 'this', name: 'this' };
  else if (/^[A-Z]\w*$/.test(head)) root = { kind: 'type', name: head };
  else if (/^[a-zA-Z_]\w*\s*\(/.test(head)) root = { kind: 'call', name: head.slice(0, head.indexOf('(')).trim() };
  else return null;   // a plain identifier, an index, an expression — not typed here

  const steps: Array<{ name: string; line: number }> = [];
  for (const raw of parts.slice(1)) {
    const p = raw.trim();
    const m = /^([a-zA-Z_]\w*)\s*\(/.exec(p);
    if (!m) return null;   // a field access mid-chain is not walked
    steps.push({ name: m[1], line: 0 });
  }
  return { root, steps };
}

function shortestPrefixes(pkgs: string[]): string[] {
  const sorted = [...pkgs].sort();
  const out: string[] = [];
  for (const p of sorted) {
    if (!out.some(o => p === o || p.startsWith(`${o}.`))) out.push(p);
  }
  return out;
}

function lastSegment(fqn: string): string {
  const i = fqn.lastIndexOf('.');
  return i === -1 ? fqn : fqn.slice(i + 1);
}

function stripLast(fqn: string): string {
  const i = fqn.lastIndexOf('.');
  return i === -1 ? '' : fqn.slice(0, i);
}

function push<T>(m: Map<string, T[]>, k: string, v: T): void {
  const cur = m.get(k);
  if (cur) cur.push(v);
  else m.set(k, [v]);
}

function push2(m: Map<string, Set<string>>, k: string, v: string): void {
  const cur = m.get(k);
  if (cur) cur.add(v);
  else m.set(k, new Set([v]));
}

/** FNV-1a over the file text. Enough to key a cache; not a security hash. */
function cheapHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

function now(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}
