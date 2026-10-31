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
 * Two more, found by asking for the callers of overloaded and of overridden
 * methods in a 6,900-file Java repository, where every such answer was wrong:
 *
 *   - **Overloads.** A call binds to one overload, chosen the way the compiler
 *     chooses — by arity, then by argument types in the compiler's three
 *     phases, then the most specific — and only where the types read off the
 *     source make the choice certain. Where they do not, the site is
 *     `unresolved` with `overload-ambiguous` and the candidates. A symbol may
 *     carry a parameter list to ask about one overload; a query without one
 *     on an overloaded method gets its answers grouped per overload.
 *   - **Dispatch.** A call through a supertype's declaration can land on an
 *     override, and a call to an override is a caller of the operation it
 *     overrides. Both are answered `polymorphic`, with `via` naming what the
 *     site binds to, and the query's `scope` says what dispatch it cannot see.
 *
 * What it deliberately does **not** do: invent a receiver type, or an
 * argument type. Where no type is known the answer is `inferred`, ambiguous,
 * or absent, and `inferred` is a permanent floor — see `Tier`.
 */

import type { CircleIR, CallInfo, ArgumentInfo, TypeInfo, SupportedLanguage } from '../types/index.js';
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

/** What `bind` decides: everything in an answer that is not about the site. */
type BoundTarget = Omit<AnswerEntry, 'site' | 'methodName'>;

/**
 * What is known about a receiver's static type.
 *
 * The distinction between `foreign` and nothing at all is the whole of the
 * `exact` promise. A receiver whose type is known to be something we do not
 * hold cannot be calling our method of that name, so the honest output is no
 * answer and a scope reason. A receiver with no type at all is a different
 * situation, and the floor tier exists for it.
 */
type ReceiverType =
  | { kind: 'project'; fqn: string; evidence: string }
  | { kind: 'foreign'; name: string; evidence: string };

/** One declaration of a method or constructor. A name can have several. */
interface Overload {
  name: string;
  /** Parameter types as written, `String...` for varargs. */
  params: string[];
  varargs: boolean;
  /** `null` for a constructor. */
  returnType: string | null;
  isConstructor: boolean;
  startLine: number;
  endLine: number;
  modifiers: string[];
  /** The method's own type parameter names. */
  typeParams: string[];
  /** Bounded ones' leftmost bound, as written. */
  typeBounds: Record<string, string>;
  /**
   * Each parameter's type as the compiler erases it — a type variable
   * replaced by its leftmost bound or `Object` — else as written. What
   * `signature` shows, so overloads differing only in a variable's bound
   * (`copy(T...)` three times) stay distinguishable.
   */
  erased: string[];
  /** For each parameter that is a type variable: its name and how certain an erased fit is. */
  vars: Array<{ name: string; certain: boolean } | null>;
}

interface TypeRecord {
  fqn: string;
  simpleName: string;
  kind: TypeInfo['kind'];
  isRecord: boolean;
  file: string;
  /** Simple names, as written in the source. */
  superNames: string[];
  /** The superclass as written, when the type names one. */
  extendsName: string | null;
  annotations: string[];
  fieldNames: string[];
  /** Field name → its type as written. */
  fieldTypes: Map<string, string>;
  /** The type's own type parameter names, in order. */
  typeParams: string[];
  /** Bounded ones' leftmost bound, as written. */
  typeBounds: Record<string, string>;
  /** Field names carrying a field-level `@Getter` / `@Setter`. */
  getterFields: string[];
  setterFields: string[];
  /** One entry per name, overloads merged: the name-level view. */
  methods: Map<string, { returnType: string | null; startLine: number; endLine: number; modifiers: string[] }>;
  /** Every declaration, by name. A constructor is filed under the type's simple name. */
  overloads: Map<string, Overload[]>;
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

/** A call target located by file and declaration line (`callSites`). */
export interface IndexedTarget {
  file: string;
  /** The declaration's first line (annotations included), as the IR reports it. */
  line: number;
  name: string;
  fqn: string;
  /** The target is the type itself (a constructor it does not declare). */
  type?: true;
}

/** One call site, bound or not (`callSites`). */
export type IndexedCallSite =
  | { site: { file: string; line: number; col: number }; methodName: string; kind: 'bound'; tier: Tier; declaring: IndexedTarget; bodies: IndexedTarget[] }
  | {
      site: { file: string; line: number; col: number };
      methodName: string;
      kind: 'unresolved';
      reason: UnresolvedReason;
      /** `external` sites: the type outside the tree the call lands on, qualified through the file's imports where they say. */
      receiver?: string;
    };

/** One overload, with the type that declares it. */
interface Candidate {
  owner: TypeRecord;
  overload: Overload;
}

/**
 * What binding a call site decides.
 *
 * `bound` names one declaration (`overload` is absent only for a constructor
 * of a type that declares none, or whose declared ones the call fits none
 * of). `ambiguous` names the type and several overloads the call could be
 * calling, which is not an answer.
 */
type Binding =
  | {
      kind: 'bound';
      owner: TypeRecord;
      name: string;
      overload?: Overload;
      /** The receiver's static type, where one was known. */
      receiver?: string;
      result: BoundTarget;
    }
  | {
      kind: 'ambiguous';
      owner: TypeRecord;
      name: string;
      candidates: Candidate[];
      receiver?: string;
      evidence: string;
    };

/** How overload selection ended. */
type Selection =
  | { kind: 'one'; pick: Candidate; how: string }
  | { kind: 'ambiguous'; candidates: Candidate[] }
  | { kind: 'none' };

/** A type as overload selection compares it: erased, with its array depth. */
interface TypeRef {
  /** Simple name, generics and qualification removed: `String`, `int`, `null`. */
  simple: string;
  /** Fully-qualified, where it could be resolved. */
  fqn: string | null;
  dims: number;
  prim: boolean;
  /** A type variable — `T`, `E` — which any reference type may fill. */
  typeVar: boolean;
  /**
   * For a type variable declared on the method or its type: the name it was
   * written with, and what it erases to — its leftmost bound, else `Object`.
   * `simple` / `fqn` / `dims` then describe the erasure.
   */
  varName?: string;
  erasure?: TypeRef;
  /**
   * A parameter whose type is a type variable the call site itself sees —
   * a generic class calling its own method — so exactly that variable: only
   * it, `null`, or a variable bounded by it can be passed.
   */
  opaque?: boolean;
  /**
   * An argument whose type is what a generic method's call infers for its
   * variable: known only to be some subtype of the erasure.
   */
  inferred?: boolean;
  /**
   * Whether an argument that fits the erasure certainly fits the variable: so
   * for a method's own unbounded or plainly bounded variable, which the
   * compiler infers from the arguments; not for the type's, which the
   * receiver fixes, nor for a bound naming a type variable itself.
   */
  certain?: boolean;
}

type Fit = 'yes' | 'maybe' | 'no';

/** A query symbol, split. */
interface ParsedSymbol {
  /** `pkg.Type.method`, without a parameter list. */
  base: string;
  owner: string;
  name: string;
  /** The parameter list, when the symbol carried one. */
  params?: string[];
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
/** What every class inherits from `java.lang.Object`. */
const OBJECT_METHODS = new Set(['toString', 'hashCode', 'equals', 'getClass', 'clone', 'finalize', 'notify', 'notifyAll', 'wait']);
const LOMBOK_ACCESSOR = new Set(['Getter', 'Setter', 'Data', 'Value']);
const LOMBOK_BUILDER = new Set(['Builder', 'SuperBuilder']);

const PRIMITIVES = new Set(['byte', 'short', 'char', 'int', 'long', 'float', 'double', 'boolean']);
/** Primitive widening: what each primitive may be passed as, itself included. */
const WIDENS_TO: Record<string, string[]> = {
  byte: ['byte', 'short', 'int', 'long', 'float', 'double'],
  short: ['short', 'int', 'long', 'float', 'double'],
  char: ['char', 'int', 'long', 'float', 'double'],
  int: ['int', 'long', 'float', 'double'],
  long: ['long', 'float', 'double'],
  float: ['float', 'double'],
  double: ['double'],
  boolean: ['boolean'],
};
const BOXES: Record<string, string> = {
  byte: 'Byte', short: 'Short', char: 'Character', int: 'Integer',
  long: 'Long', float: 'Float', double: 'Double', boolean: 'Boolean',
};
const UNBOXES: Record<string, string> = Object.fromEntries(Object.entries(BOXES).map(([p, b]) => [b, p]));
/**
 * JDK classes whose supertypes are known here, so a value of one can be ruled
 * in or out of a parameter type without the JDK on hand. Every one is a class,
 * not an interface; the `final` ones can only ever be themselves.
 */
const JDK_SUPERS: Record<string, { final: boolean; supers: string[] }> = (() => {
  const num = ['Number', 'Comparable', 'Serializable', 'Object'];
  const temporal = ['Temporal', 'TemporalAccessor', 'TemporalAdjuster', 'Comparable', 'Serializable', 'Object'];
  return {
    String: { final: true, supers: ['CharSequence', 'Comparable', 'Serializable', 'Constable', 'ConstantDesc', 'Object'] },
    Long: { final: true, supers: num }, Integer: { final: true, supers: num },
    Short: { final: true, supers: num }, Byte: { final: true, supers: num },
    Double: { final: true, supers: num }, Float: { final: true, supers: num },
    Boolean: { final: true, supers: ['Comparable', 'Serializable', 'Object'] },
    Character: { final: true, supers: ['Comparable', 'Serializable', 'Object'] },
    BigDecimal: { final: false, supers: num }, BigInteger: { final: false, supers: num },
    LocalDate: { final: true, supers: ['ChronoLocalDate', ...temporal] },
    LocalDateTime: { final: true, supers: ['ChronoLocalDateTime', ...temporal] },
    LocalTime: { final: true, supers: temporal },
    ZonedDateTime: { final: true, supers: ['ChronoZonedDateTime', ...temporal] },
    OffsetDateTime: { final: true, supers: temporal },
    Instant: { final: true, supers: temporal },
    Duration: { final: true, supers: ['TemporalAmount', 'Comparable', 'Serializable', 'Object'] },
    Period: { final: true, supers: ['ChronoPeriod', 'TemporalAmount', 'Serializable', 'Object'] },
    UUID: { final: true, supers: ['Comparable', 'Serializable', 'Object'] },
    Locale: { final: true, supers: ['Cloneable', 'Serializable', 'Object'] },
    Class: { final: true, supers: ['Type', 'GenericDeclaration', 'AnnotatedElement', 'Serializable', 'Object'] },
    Date: { final: false, supers: ['Cloneable', 'Comparable', 'Serializable', 'Object'] },
    StringBuilder: { final: true, supers: ['CharSequence', 'Appendable', 'Comparable', 'Serializable', 'Object'] },
    Object: { final: false, supers: [] },
  };
})();
/** JDK interfaces with no supertype of their own. */
const LEAF_INTERFACES = new Set(['Serializable', 'Cloneable', 'Comparable', 'AutoCloseable', 'Runnable', 'Iterable', 'CharSequence']);
const JAVA_LANG = new Set([
  'String', 'Long', 'Integer', 'Short', 'Byte', 'Double', 'Float', 'Boolean', 'Character',
  'Object', 'Number', 'Class', 'StringBuilder', 'CharSequence', 'Comparable', 'Iterable', 'Enum',
]);

/** Bumped when the shape of a cached per-file record changes. */
const CACHE_VERSION = 'nav-4';
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
  /** A call's binding, once made. The index is immutable, so it never goes stale. */
  private readonly bindings = new Map<CallInfo, Binding | null>();
  /** Calls by `line:column`, per file, built on first use. */
  private readonly callsAt = new Map<string, Map<string, CallInfo[]>>();

  constructor(input: NavigationFile[], options: BuildOptions) {
    const t0 = now();
    // A file in a language this index cannot resolve is **not searched**, and
    // the scope must say so. Reporting it as searched was the first graded
    // record's `:denominator-stated` deviation: four languages named, one
    // resolved, and a file count a caller could divide an answer by and get
    // a ratio that means nothing. The decline is recorded by language name,
    // with the vocabulary reason, on every answer.
    const declined = new Set<string>();
    for (const f of input) {
      if (!this.parses(f.language)) {
        declined.add(f.language);
        continue;
      }
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
      excluded: [
        ...(options.excluded ?? []),
        ...[...declined].sort().map(lang => ({
          pattern: lang,
          reason: `unsupported-language: this index resolves ${languages.join(', ') || 'no language'}`,
        })),
      ],
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
   *
   * An overloaded method is answered per overload: with a parameter list in
   * the symbol, for that overload alone; without one, for every overload,
   * grouped and labelled, with a `note` saying so.
   */
  resolveCallers(query: Query, opts: QueryOptions = {}): NavigationAnswer {
    const t0 = now();
    const symbol = this.querySymbol(query, 'callers');
    const answers: AnswerEntry[] = [];
    const unresolved: UnresolvedEntry[] = [];

    if (symbol === undefined) {
      return this.finish('callers', query, answers, unresolved, t0, opts);
    }
    const q = parseSymbol(symbol);
    const target = this.typesByFqn.get(q.owner);
    const declared = target ? this.declaredOverloads(target, q.name) : [];
    const wanted = q.params ? declared.filter(o => this.signatureMatches(o, q.params!, target!)) : declared;
    const overloaded = declared.length > 1;
    const extra: Pick<NavigationAnswer, 'note' | 'overloads'> = {};

    if (q.params && target && declared.length > 0 && wanted.length === 0) {
      extra.note =
        `no overload of ${q.base} has the parameter list (${q.params.join(',')}); ` +
        `declared: ${declared.map(o => `${q.base}${signatureOf(o)}`).join(', ')}`;
      return this.finish('callers', query, answers, unresolved, t0, opts, extra);
    }
    if (target && declared.length === 0 && q.name !== '<init>' && this.visibleOverloads(target.fqn, q.name).length === 0) {
      // `MapIterator.toString()`: the type is in the tree, the method is
      // not — it is inherited from outside, so no call site can bind to the
      // query's target, and "no callers" would read as a finding.
      extra.note =
        `${q.owner} declares no method ${q.name}, and no supertype in the searched tree does: it is inherited from ` +
        `${OBJECT_METHODS.has(q.name) ? 'java.lang.Object' : 'a type outside the tree'}, so no call site here binds to ${q.base}. ` +
        `A call reached only through string conversion or library code has no call site at all.`;
    }
    const wantedSet = new Set(wanted);
    const dispatchOpen = target !== undefined && q.name !== '<init>' && wanted.some(o => this.dispatchIsOpen(target, o));

    for (const rec of this.files.values()) {
      for (const call of rec.calls) {
        if (!this.nameCouldMatch(call, q.name, q.owner)) continue;
        const b = this.bindCall(call, rec);
        if (!b) {
          unresolved.push({
            site: this.siteOf(call, rec),
            reason: this.reasonFor(call, rec),
            methodName: call.method_name,
          });
          continue;
        }
        if (!target) continue;

        if (b.kind === 'ambiguous') {
          // Ambiguous among overloads none of which is the target is not this
          // query's business; among overloads that include it, it is the
          // honest half of the answer.
          const relevant = b.candidates.some(
            c => (c.owner === target && wantedSet.has(c.overload)) || this.dispatchRelation(c.owner, c.overload, b.receiver, target, wanted) !== undefined,
          );
          if (relevant) {
            unresolved.push({
              site: this.siteOf(call, rec),
              reason: 'overload-ambiguous',
              methodName: call.method_name,
              candidates: b.candidates.map(c => `${memberName(c.owner, c.overload)}${signatureOf(c.overload)}`),
            });
          }
          continue;
        }

        if (b.owner === target && b.name === q.name) {
          if (!b.overload) {
            // A constructor call that fits none of the declared constructors,
            // or a type that declares none: the type is certain, the overload
            // is not, so a query about one overload cannot count it.
            if (q.params && declared.length > 0) {
              unresolved.push({
                site: this.siteOf(call, rec),
                reason: 'overload-ambiguous',
                methodName: call.method_name,
                candidates: declared.map(o => `${q.base}${signatureOf(o)}`),
              });
            } else {
              answers.push({ ...b.result, methodName: call.method_name, site: this.siteOf(call, rec) });
            }
            continue;
          }
          if (!wantedSet.has(b.overload)) continue;   // another overload: answered elsewhere
          answers.push({
            ...b.result,
            ...(overloaded ? { signature: signatureOf(b.overload) } : {}),
            methodName: call.method_name,
            site: this.siteOf(call, rec),
          });
          continue;
        }

        if (!dispatchOpen || !b.overload) continue;
        const rel = this.dispatchRelation(b.owner, b.overload, b.receiver, target, wanted);
        if (!rel) continue;
        const via = `${memberName(b.owner, b.overload)}`;
        answers.push({
          target: q.base,
          tier: 'polymorphic',
          ...(b.result.candidates ? { candidates: b.result.candidates } : {}),
          ...(overloaded ? { signature: signatureOf(rel.overload) } : {}),
          via: { member: via, relation: rel.relation },
          evidence:
            rel.relation === 'supertype'
              ? `the site calls ${via}, declared on supertype ${b.owner.fqn}; ${q.base} overrides it, so the call lands on it when the receiver is a ${target.fqn}`
              : `the site calls ${via}, which overrides ${q.base}; it reaches ${q.base}'s body only through super, and is a caller of the operation ${q.base} declares`,
          methodName: call.method_name,
          site: this.siteOf(call, rec),
        });
      }
    }

    if (overloaded && !q.params) {
      extra.overloads = declared.map(o => ({
        signature: signatureOf(o),
        answers: answers.filter(a => a.signature === signatureOf(o)).length,
      }));
      extra.note = `${declared.length} overloads; pass a signature to narrow, e.g. ${q.base}${signatureOf(declared[0])}`;
    }
    const scope = dispatchOpen ? this.dispatchScope(q.base) : undefined;
    return this.finish('callers', query, answers, unresolved, t0, opts, extra, scope);
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
    const q = parseSymbol(symbol);
    const owner = this.typesByFqn.get(q.owner);
    const declared = owner ? this.declaredOverloads(owner, q.name) : [];
    const bodies = q.params ? declared.filter(o => this.signatureMatches(o, q.params!, owner!)) : declared;
    if (!owner || bodies.length === 0) {
      return this.finish('callees', query, answers, unresolved, t0, opts);
    }
    const rec = this.files.get(owner.file);
    if (!rec) return this.finish('callees', query, answers, unresolved, t0, opts);

    for (const call of rec.calls) {
      const line = call.location.line;
      if (!bodies.some(o => line >= o.startLine && line <= o.endLine)) continue;
      const b = this.bindCall(call, rec);
      if (b?.kind === 'bound') {
        answers.push({
          ...b.result,
          ...(b.overload && this.declaredOverloads(b.owner, b.name).length > 1 ? { signature: signatureOf(b.overload) } : {}),
          methodName: call.method_name,
          site: this.siteOf(call, rec),
        });
      } else if (b?.kind === 'ambiguous') {
        unresolved.push({
          site: this.siteOf(call, rec),
          reason: 'overload-ambiguous',
          methodName: call.method_name,
          candidates: b.candidates.map(c => `${memberName(c.owner, c.overload)}${signatureOf(c.overload)}`),
        });
      } else {
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
   * Every call site in the index, bound — the whole-program view of what
   * `resolveCallees` answers one method at a time, with each target located
   * by file and declaration line so a caller can key it to its own
   * declaration ids. Additive: no query path changes.
   *
   * A `bound` site names the member its receiver's static type declares
   * (`declaring`) and, on `polymorphic`, every body that could run
   * (`bodies`, the overload with the declaring member's signature where it
   * has one). Anything else is `unresolved` with the same reason a query
   * would give.
   */
  callSites(): IndexedCallSite[] {
    const out: IndexedCallSite[] = [];
    const files = [...this.files.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    for (const rec of files) {
      for (const call of rec.calls) {
        const site = { file: rec.path, line: call.location.line, col: call.location.column };
        const b = this.bindCall(call, rec);
        if (b?.kind === 'bound') {
          const bodies: IndexedTarget[] = [];
          if (b.result.tier === 'polymorphic') {
            const sig = b.overload ? signatureOf(b.overload) : null;
            for (const c of b.result.candidates ?? []) {
              const dot = c.lastIndexOf('.');
              const t = this.typesByFqn.get(c.slice(0, dot));
              const name = c.slice(dot + 1);
              if (!t) continue;
              const all = this.declaredOverloads(t, name);
              const pick = sig ? all.filter(o => signatureOf(o) === sig) : all;
              for (const o of pick.length > 0 ? pick : all) bodies.push({ file: t.file, line: o.startLine, name, fqn: c });
            }
          }
          out.push({ site, methodName: call.method_name, kind: 'bound', tier: b.result.tier, declaring: this.targetOf(b.owner, b.name, b.overload), bodies });
        } else {
          const reason = b?.kind === 'ambiguous' ? 'overload-ambiguous' : this.reasonFor(call, rec);
          const receiver = reason === 'external' ? this.foreignTypeOf(call, rec) : undefined;
          out.push({ site, methodName: call.method_name, kind: 'unresolved', reason, ...(receiver ? { receiver } : {}) });
        }
      }
    }
    return out;
  }

  /** The type outside the tree an `external` site lands on: its receiver, the constructed type, or a static import's owner. */
  private foreignTypeOf(call: CallInfo, rec: FileRecord): string | undefined {
    let name: string | undefined;
    if (call.is_constructor) name = call.receiver_type_fqn ?? call.receiver_type ?? call.method_name;
    else if (call.receiver === null && !call.receiver_type) name = rec.staticImports.get(call.method_name);
    else {
      const t = this.receiverTypeOf(call, rec);
      if (t?.kind === 'foreign') name = t.name;
    }
    const bare = name?.replace(/<.*>$/, '').replace(/\[\]$/, '').trim();
    if (!bare) return undefined;
    return bare.includes('.') ? bare : rec.imports.get(bare) ?? bare;
  }

  private targetOf(owner: TypeRecord, name: string, overload: Overload | undefined): IndexedTarget {
    if (overload) return { file: owner.file, line: overload.startLine, name: overload.isConstructor ? '<init>' : name, fqn: memberName(owner, overload) };
    const m = name === '<init>' ? undefined : owner.methods.get(name);
    if (m) return { file: owner.file, line: m.startLine, name, fqn: `${owner.fqn}.${name}` };
    // A constructor the type does not declare: the type itself.
    return { file: owner.file, line: owner.startLine, name: owner.simpleName, fqn: owner.fqn, type: true };
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
   * line — "what does the method I am looking at call". Either carries a
   * parameter list when the name is overloaded, so the follow-up query asks
   * about that overload alone. Returns nothing when the site names no call,
   * when the call cannot be bound to one target, or when the name is written
   * twice on one line, which the key cannot separate.
   */
  symbolAt(
    file: string,
    line: number,
    methodName: string,
    kind: QueryKind,
  ): string | undefined {
    const rec = this.files.get(file);
    if (!rec) return undefined;

    if (kind === 'callees') return this.methodAt(rec, line);

    const at = rec.calls.filter(
      (c) => c.location.line === line && c.method_name === methodName,
    );
    // The same name twice on one line is beyond this key, and picking one of
    // them would be a guess presented as an answer.
    if (at.length !== 1) return undefined;
    return this.symbolOfCall(at[0], rec);
  }

  // ------------------------------------------------------------ the binding

  /** `bindCall`, reduced to what callers outside the query paths need. */
  private symbolOfCall(call: CallInfo, rec: FileRecord): string | undefined {
    const b = this.bindCall(call, rec);
    if (b?.kind !== 'bound') return undefined;
    if (b.overload && this.declaredOverloads(b.owner, b.name).length > 1) {
      return `${b.result.target}${signatureOf(b.overload)}`;
    }
    return b.result.target;
  }

  /**
   * Bind one call site to a target, to several candidates, or to nothing.
   *
   * The order matters and is the whole contract: a receiver type is sought
   * first, and only when none can be had does a name-only bind happen, which
   * is labelled `inferred` and never anything better. Within the type the
   * receiver names, the overload is chosen by `selectOverload`, and a choice
   * it cannot make is `ambiguous`, not a pick.
   */
  private bindCall(call: CallInfo, rec: FileRecord, depth = 0): Binding | undefined {
    const memo = this.bindings.get(call);
    if (memo !== undefined) return memo ?? undefined;
    const b = this.bindUncached(call, rec, depth);
    // A bind made too deep inside another call's argument typing may have
    // been cut short, so only a top-level result is remembered.
    if (depth === 0) this.bindings.set(call, b ?? null);
    return b;
  }

  private bindUncached(call: CallInfo, rec: FileRecord, depth: number): Binding | undefined {
    // A constructor arrives as a call named after the type, with no receiver.
    const ctor = this.bindConstructor(call, rec, depth);
    if (ctor) return ctor;

    const recv = this.receiverTypeOf(call, rec);

    // The receiver's type is known and is not ours. Binding by name here is
    // precisely the contradiction the contract forbids: on a 405-file
    // repository, 78 of 147 name-only "callers" of one method had a receiver
    // whose own declared type could not have that method. A known foreign type
    // is an answer about scope, not a weak answer about a target.
    if (recv?.kind === 'foreign') return undefined;

    if (recv?.kind === 'project') {
      // The receiver's type is known; a method it does not have (at this
      // arity) would be the contradiction the audit found 78 of, so no.
      return this.bindInType(recv.fqn, call, rec, depth, recv.evidence, recv.fqn);
    }

    // `super.m()` names the superclass's member outright.
    if (call.receiver === 'super') {
      const encl = this.enclosingTypeOf(call, rec);
      const sup = encl?.extendsName ? this.resolveTypeName(encl.extendsName, rec) : undefined;
      if (sup && this.typesByFqn.has(sup)) {
        return this.bindInType(sup, call, rec, depth, `super call inside ${encl!.fqn}`, sup, true);
      }
      return undefined;
    }

    // A statically imported member names its owner outright.
    const owner = this.staticOwnerFor(call, rec);
    if (owner) {
      const b = this.bindInType(owner.fqn, call, rec, depth, owner.evidence, undefined);
      if (b) return b;
    }

    // No receiver at all: an unqualified call is `this` or the enclosing type's
    // own static method. The enclosing type is known exactly, so this is not a
    // guess — but it is still only a *declaration*, and the first graded record
    // caught this path handing out `exact` on an abstract member whose body
    // lives in a subclass. Every path to a target now goes through `tierFor`.
    if (call.receiver === null && !call.receiver_type) {
      const encl = this.enclosingTypeOf(call, rec);
      if (encl && this.lookupThroughHierarchy(encl.fqn, call.method_name)) {
        return this.bindInType(encl.fqn, call, rec, depth, `unqualified call inside ${encl.fqn}`, encl.fqn);
      }
    }

    // Nothing typed the receiver. A name-only bind is the floor, and only when
    // the name is unambiguous in the tree — a name owned by several types is
    // not evidence of anything.
    const byName = this.uniqueByName(call.method_name);
    if (byName) {
      const evidence = `bound by method name alone — no receiver type was available; ${call.method_name} is declared exactly once in the searched tree, on ${byName.fqn}`;
      const cands = this.visibleOverloads(byName.fqn, call.method_name);
      const sel = this.selectOverload(cands, call, rec, depth);
      if (sel.kind === 'ambiguous') {
        return { kind: 'ambiguous', owner: byName, name: call.method_name, candidates: sel.candidates, evidence };
      }
      if (sel.kind === 'none') return undefined;
      return {
        kind: 'bound',
        owner: sel.pick.owner,
        name: call.method_name,
        overload: sel.pick.overload,
        result: { target: `${sel.pick.owner.fqn}.${call.method_name}`, tier: 'inferred', evidence },
      };
    }
    return undefined;
  }

  /** Bind `call` to a member of `fqn` or of a supertype of it, choosing the overload. */
  private bindInType(
    fqn: string,
    call: CallInfo,
    rec: FileRecord,
    depth: number,
    evidence: string,
    receiver: string | undefined,
    nonVirtual = false,
  ): Binding | undefined {
    const cands = this.visibleOverloads(fqn, call.method_name);
    if (cands.length === 0) return undefined;
    const sel = this.selectOverload(cands, call, rec, depth);
    if (sel.kind === 'none') return undefined;
    if (sel.kind === 'ambiguous') {
      const owner = sel.candidates[0].owner;
      return { kind: 'ambiguous', owner, name: call.method_name, candidates: sel.candidates, receiver, evidence };
    }
    const { owner, overload } = sel.pick;
    const overloaded = this.declaredOverloads(owner, call.method_name).length > 1 || cands.length > 1;
    return {
      kind: 'bound',
      owner,
      name: call.method_name,
      overload,
      receiver,
      result: overloaded
        ? this.tierFor(owner, call.method_name, overload, `${evidence}; ${sel.how}`, true, nonVirtual)
        : this.tierFor(owner, call.method_name, overload, evidence, false, nonVirtual),
    };
  }

  /**
   * The tier for a target, once the declaring type is known.
   *
   * Every path to an answer goes through here, which is the point: the
   * body-required rule was added in one place and the first graded record
   * found it missing from another. `exact` is a promise that the target named
   * is the code that runs, so it needs two things — the declaring type known,
   * and the declaration **having a body**. An abstract member satisfies only
   * the first; what runs there is a subclass's body or a lambda, never the
   * member named. The target stays the declaring member, which is what a
   * static resolver answers; only the tier changes.
   *
   * A `super.m()` call is not dispatched: it runs the body it names, whatever
   * overrides it below.
   */
  private tierFor(
    owner: TypeRecord,
    method: string,
    overload: Overload,
    evidence: string,
    overloaded = false,
    nonVirtual = false,
  ): BoundTarget {
    const impls = this.implementorsWith(owner.fqn, overload);
    const bodyless = this.isBodyless(owner, overload);
    if ((impls.length > 1 && !nonVirtual) || bodyless) {
      return {
        target: `${owner.fqn}.${method}`,
        tier: 'polymorphic',
        candidates: impls.map(t => `${t}.${method}`),
        evidence: bodyless && impls.length === 0
          ? `${evidence}; ${method} is declared without a body on ${owner.kind} ${owner.fqn} and nothing in the searched tree implements it — what runs is an implementation or a lambda outside this index`
          : `${evidence}; ${method} is declared on ${owner.kind} ${owner.fqn} with ${impls.length} implementor(s) in the searched tree`,
      };
    }
    return {
      target: `${owner.fqn}.${method}`,
      tier: 'exact',
      evidence: overloaded
        ? `${evidence}; it is declared on ${owner.fqn}, and it has a body`
        : `${evidence}; ${method} is the unique method of that name on ${owner.fqn}, and it has a body`,
    };
  }

  /** `new Widget()` → `app.Widget.<init>`, with the constructor chosen like any overload. */
  private bindConstructor(call: CallInfo, rec: FileRecord, depth: number): Binding | undefined {
    const looksCtor =
      call.is_constructor === true ||
      (call.receiver === null &&
        !!call.receiver_type &&
        call.receiver_type === call.method_name &&
        /^[A-Z]/.test(call.method_name));
    if (!looksCtor) return undefined;
    const t = this.resolveTypeRecord(call.receiver_type ?? call.method_name, rec);
    if (!t) return undefined;
    const result: BoundTarget = {
      target: `${t.fqn}.<init>`,
      tier: 'exact',
      evidence: `object creation of ${t.fqn}, declared at ${t.file}:${t.startLine}`,
    };
    const ctors = this.declaredOverloads(t, '<init>').map(overload => ({ owner: t, overload }));
    // A type with no declared constructor has the implicit one; a call that
    // fits none of the declared ones (a record's canonical constructor, say)
    // still certainly creates this type. Either way the type is the answer
    // and the overload is not known.
    if (ctors.length === 0) return { kind: 'bound', owner: t, name: '<init>', result };
    const sel = this.selectOverload(ctors, call, rec, depth);
    if (sel.kind === 'ambiguous') {
      return { kind: 'ambiguous', owner: t, name: '<init>', candidates: sel.candidates, evidence: result.evidence ?? '' };
    }
    if (sel.kind === 'none') return { kind: 'bound', owner: t, name: '<init>', result };
    return {
      kind: 'bound',
      owner: t,
      name: '<init>',
      overload: sel.pick.overload,
      result: ctors.length > 1 ? { ...result, evidence: `${result.evidence}; ${sel.how}` } : result,
    };
  }

  // ---------------------------------------------------- overload selection

  /**
   * The overloads of `name` a receiver of type `fqn` can see: its own, then
   * its supertypes', nearest first, leaving out any a nearer type overrides.
   */
  private visibleOverloads(fqn: string, name: string): Candidate[] {
    const out: Candidate[] = [];
    const seen = new Set<string>();
    const queue = [fqn];
    while (queue.length > 0) {
      const f = queue.shift()!;
      if (seen.has(f)) continue;
      seen.add(f);
      const t = this.typesByFqn.get(f);
      if (!t) continue;
      for (const o of t.overloads.get(name) ?? []) {
        if (o.isConstructor) continue;
        if (out.some(c => this.sameErasure(c, { owner: t, overload: o }))) continue;
        out.push({ owner: t, overload: o });
      }
      const rec = this.files.get(t.file);
      for (const sup of t.superNames) {
        const supFqn = rec ? this.resolveTypeName(sup, rec) : undefined;
        if (supFqn) queue.push(supFqn);
      }
    }
    return out;
  }

  /** The declarations of `name` on `t` itself. `<init>` is its constructors. */
  private declaredOverloads(t: TypeRecord, name: string): Overload[] {
    if (name === '<init>') return (t.overloads.get(t.simpleName) ?? []).filter(o => o.isConstructor);
    return (t.overloads.get(name) ?? []).filter(o => !o.isConstructor);
  }

  /**
   * Choose the overload a call invokes, the way the compiler does — or say
   * that the types read off the source do not decide it.
   *
   * Arity first. Then the compiler's three phases: without boxing or
   * varargs, with boxing, with varargs. In the first phase that has any
   * applicable overload, the most specific one wins. Every argument type here
   * is a lower bound on what is known — an argument that cannot be typed fits
   * anything — so the rule is applied only where it is sound: an overload is
   * picked when it is **certainly** applicable and more specific than every
   * overload that **might** be. Anything less is `ambiguous`.
   */
  private selectOverload(cands: Candidate[], call: CallInfo, rec: FileRecord, depth: number): Selection {
    const n = call.arguments.length;
    const byArity = cands.filter(c => fitsArity(c.overload, n));
    if (byArity.length === 0) return { kind: 'none' };
    const args = call.arguments.map(a => this.argumentType(a, call, rec, depth));
    // An implicit, `this.` or `super.` receiver is the enclosing type itself,
    // which fixes what the declaring type's variables are.
    const self = call.receiver === null || call.receiver === 'this' || call.receiver === 'super'
      ? this.enclosingTypeOf(call, rec)
      : undefined;
    if (byArity.length === 1) {
      // The only declaration in the tree at this arity, but the argument
      // types certainly rule it out: what is called is an overload this
      // index cannot see, inherited from a library type. Not ours.
      if ([1, 2, 3].every(p => this.applicable(byArity[0], args, p, self) === 'no')) return { kind: 'none' };
      return {
        kind: 'one',
        pick: byArity[0],
        how: `overload ${signatureOf(byArity[0].overload)} is the only one taking ${n} argument(s)`,
      };
    }
    const fit = new Map<Candidate, Fit[]>();
    for (const c of byArity) fit.set(c, [1, 2, 3].map(p => this.applicable(c, args, p, self)));

    const possible = byArity.filter(c => fit.get(c)!.some(f => f !== 'no'));
    if (possible.length === 1) {
      return {
        kind: 'one',
        pick: possible[0],
        how: `overload ${signatureOf(possible[0].overload)} is the only one the argument types admit`,
      };
    }
    // The argument types rule out every overload: something read off the
    // source is wrong, so nothing is chosen.
    if (possible.length === 0) return { kind: 'ambiguous', candidates: byArity };

    for (const phase of [1, 2, 3]) {
      const P = possible.filter(c => fit.get(c)![phase - 1] !== 'no');
      if (P.length === 0) continue;
      const C = P.filter(c => fit.get(c)![phase - 1] === 'yes');
      if (C.length === 0) return { kind: 'ambiguous', candidates: possible };
      const best = C.find(m => P.every(o => o === m || this.moreSpecific(m, o, phase, self)));
      if (best) {
        return {
          kind: 'one',
          pick: best,
          how: `overload ${signatureOf(best.overload)} is the most specific one the argument types admit`,
        };
      }
      return { kind: 'ambiguous', candidates: P };
    }
    return { kind: 'ambiguous', candidates: possible };
  }

  /** Whether `c` applies to arguments of these types in compiler phase 1, 2 or 3. */
  private applicable(c: Candidate, args: Array<TypeRef | null>, phase: number, self?: TypeRecord): Fit {
    const o = c.overload;
    const params = this.paramRefsFrom(c, self);
    let worst: Fit = 'yes';
    const meet = (f: Fit): void => {
      if (f === 'no') worst = 'no';
      else if (f === 'maybe' && worst === 'yes') worst = 'maybe';
    };
    if (phase < 3) {
      if (args.length !== params.length) return 'no';
      args.forEach((a, i) => meet(this.fits(a, params[i], phase)));
      return worst;
    }
    if (!o.varargs || args.length < params.length - 1) return 'no';
    const elem = elementOf(params[params.length - 1]);
    args.forEach((a, i) => meet(this.fits(a, i < params.length - 1 ? params[i] : elem, 2)));
    return worst;
  }

  /** `m` is more specific than `o`: each of its parameter types fits the other's. */
  private moreSpecific(m: Candidate, o: Candidate, phase: number, self?: TypeRecord): boolean {
    if (phase === 3) return false;
    const mp = this.paramRefsFrom(m, self);
    const op = this.paramRefsFrom(o, self);
    if (mp.length !== op.length) return false;
    return mp.every((t, i) => this.fits(t, op[i], 1) === 'yes');
  }

  /**
   * Whether a value of type `a` can be passed as `p` — certainly, possibly,
   * or certainly not. `a === null` is an argument that could not be typed.
   */
  private fits(a: TypeRef | null, p: TypeRef, phase: number): Fit {
    if (!a) return 'maybe';
    if (p.opaque) {
      if (a.simple === 'null' && a.dims === 0) return 'yes';
      if (a.typeVar) return a.varName !== undefined && a.varName === p.varName && a.dims === p.dims ? 'yes' : 'maybe';
      // Nothing but the variable itself is a subtype of it.
      return a.prim || a.fqn ? 'no' : 'maybe';
    }
    if (p.typeVar) {
      // Whatever fills a type variable is a subtype of its erasure, so an
      // argument the erasure rules out is ruled out. One it admits is
      // certainly admitted only where the compiler infers the variable from
      // the arguments.
      if (p.erasure) {
        const f = this.fits(a, p.erasure, phase);
        return f === 'no' ? 'no' : p.certain ? f : 'maybe';
      }
      return a.prim && a.dims === 0 && phase === 1 ? 'no' : 'maybe';
    }
    if (a.simple === 'null' && a.dims === 0) return p.prim && p.dims === 0 ? 'no' : 'yes';
    if (a.typeVar) {
      // A value of a type variable is a value of its erasure, and maybe of
      // something narrower.
      // A type variable's supertypes are its bound's; what a generic call
      // infers is only known to be below the erasure.
      if (a.erasure) {
        // An unbounded variable's only supertype is Object.
        if (!a.inferred && a.erasure.fqn === 'java.lang.Object' && a.erasure.dims === 0) {
          return !p.prim && p.dims === 0 && p.simple === 'Object' && (!p.fqn || p.fqn === 'java.lang.Object') ? 'yes' : 'no';
        }
        const f = this.fits(a.erasure, p, phase);
        return a.inferred && f !== 'yes' ? 'maybe' : f;
      }
      return 'maybe';
    }
    if (a.dims > 0 || p.dims > 0) {
      if (a.dims === p.dims) {
        const ae = { ...a, dims: 0 };
        const pe = { ...p, dims: 0 };
        if (ae.prim || pe.prim) return ae.prim && pe.prim && ae.simple === pe.simple ? 'yes' : 'no';
        return this.fits(ae, pe, 1);
      }
      if (a.dims > 0 && p.dims === 0) {
        if (['Object', 'Cloneable', 'Serializable'].includes(p.simple)) return 'yes';
        return p.prim || this.isProjectRef(p) || p.simple in JDK_SUPERS ? 'no' : 'maybe';
      }
      if (a.dims > p.dims && p.simple === 'Object' && !p.prim) return 'yes';
      return 'no';
    }
    if (a.prim && p.prim) return WIDENS_TO[a.simple]?.includes(p.simple) ? 'yes' : 'no';
    if (a.prim) {
      if (phase === 1) return 'no';
      const boxed = BOXES[a.simple];
      return boxed ? this.refFits({ simple: boxed, fqn: `java.lang.${boxed}`, dims: 0, prim: false, typeVar: false }, p) : 'no';
    }
    if (p.prim) {
      if (phase === 1) return 'no';
      const unboxed = UNBOXES[a.simple];
      if (unboxed && (!a.fqn || a.fqn === `java.lang.${a.simple}`)) return WIDENS_TO[unboxed].includes(p.simple) ? 'yes' : 'no';
      return this.isProjectRef(a) || a.simple in JDK_SUPERS ? 'no' : 'maybe';
    }
    return this.refFits(a, p);
  }

  /** Reference to reference: subtyping, as far as the tree and the JDK table know it. */
  private refFits(a: TypeRef, p: TypeRef): Fit {
    if (a.fqn && p.fqn && a.fqn === p.fqn) return 'yes';
    if (p.simple === 'Object' && (!p.fqn || p.fqn === 'java.lang.Object')) return 'yes';
    const aProject = this.isProjectRef(a);
    const pProject = this.isProjectRef(p);
    if (aProject) {
      const sup = this.supertypesOf(a.fqn!);
      if (pProject) {
        if (sup.project.has(p.fqn!)) return 'yes';
        // A library type never extends one of ours, so only a supertype name
        // this index could not resolve keeps the door open.
        return sup.unresolved.length > 0 ? 'maybe' : 'no';
      }
      if (sup.foreign.includes(p.simple)) return 'yes';
      // Every supertype is in the tree or a JDK type whose own supertypes are
      // known, and none of them is `p`: it cannot be one.
      const closed = sup.unresolved.length === 0 && sup.foreign.every(f => LEAF_INTERFACES.has(f) || (JDK_SUPERS[f] && !JDK_SUPERS[f].supers.includes(p.simple)));
      if (closed && this.isKnownForeignRef(p)) return 'no';
      const jdk = JDK_SUPERS[p.simple];
      if (jdk) {
        // A JDK class (not interface) is reachable only through a superclass
        // chain that leaves the tree.
        return sup.foreignClassChain ? 'maybe' : 'no';
      }
      return 'maybe';
    }
    if (pProject) {
      // A library type cannot be a subtype of a type in this tree. Only an
      // argument whose type could not be placed at all might still be ours.
      return a.fqn || a.simple in JDK_SUPERS ? 'no' : 'maybe';
    }
    if (a.simple === p.simple) return a.fqn && p.fqn && a.fqn !== p.fqn ? 'no' : 'yes';
    const ja = JDK_SUPERS[a.simple];
    if (ja) {
      if (ja.supers.includes(p.simple)) return 'yes';
      if (p.simple in JDK_SUPERS) return 'no';
      return ja.final ? 'no' : 'maybe';
    }
    const jp = JDK_SUPERS[p.simple];
    if (jp?.final) return 'no';
    return 'maybe';
  }

  /** Is `t` certainly a type outside this tree? */
  private isKnownForeignRef(t: TypeRef): boolean {
    if (t.fqn) return !this.isProjectFqn(t.fqn) && !this.typesByFqn.has(t.fqn);
    return JAVA_LANG.has(t.simple) || t.simple in JDK_SUPERS;
  }

  /** Is `t` a type declared in this tree? */
  private isProjectRef(t: TypeRef): boolean {
    return !!t.fqn && this.typesByFqn.has(t.fqn);
  }

  /** Every supertype of a project type, split into what the tree holds and what it does not. */
  private supertypesOf(fqn: string): {
    project: Set<string>;
    foreign: string[];
    unresolved: string[];
    foreignClassChain: boolean;
  } {
    const project = new Set<string>();
    const foreign: string[] = [];
    const unresolved: string[] = [];
    let foreignClassChain = false;
    const walk = (f: string, viaClass: boolean): void => {
      if (project.has(f)) return;
      project.add(f);
      const t = this.typesByFqn.get(f);
      const rec = t ? this.files.get(t.file) : undefined;
      if (!t || !rec) return;
      for (const sup of t.superNames) {
        const resolved = this.resolveTypeName(sup, rec);
        const isClassEdge = viaClass && sup === t.extendsName;
        if (resolved && this.typesByFqn.has(resolved)) {
          walk(resolved, isClassEdge);
          continue;
        }
        const simple = eraseType(sup).split('.').pop() ?? sup;
        if (this.isKnownForeign(sup, rec)) foreign.push(simple);
        else unresolved.push(simple);
        if (isClassEdge) foreignClassChain = true;
      }
    };
    walk(fqn, true);
    return { project, foreign, unresolved, foreignClassChain };
  }

  /** A type name that certainly names something outside the tree. */
  private isKnownForeign(name: string, rec: FileRecord): boolean {
    const bare = eraseType(name);
    const simple = bare.split('.').pop() ?? bare;
    if (bare.includes('.')) return !this.isProjectFqn(bare);
    const imported = rec.imports.get(simple);
    if (imported) return !this.isProjectFqn(imported);
    return JAVA_LANG.has(simple) || simple in JDK_SUPERS;
  }

  /**
   * The static type of one argument, or `null` when it cannot be known. The
   * extractor types what the syntax and the declarations in scope say; an
   * argument that is itself a call is typed here by binding that call and
   * reading the chosen overload's return type.
   */
  private argumentType(arg: ArgumentInfo, call: CallInfo, rec: FileRecord, depth: number): TypeRef | null {
    if (arg.type) return this.callSiteRef(arg.type, call, rec);
    if (!arg.location || depth >= 4) return null;
    const name = outerCallName(arg.expression);
    if (!name) return null;
    const inner = this.callAt(rec, arg.location.line, arg.location.column, name);
    if (!inner || inner === call) return null;
    const b = this.bindCall(inner, rec, depth + 1);
    let returned: { text: string; owner: TypeRecord } | undefined;
    let receiver: string | undefined;
    if (b?.kind === 'bound' && b.overload?.returnType) {
      // `<M extends Map<K, V>> M invert(…)` returns whatever the call infers
      // for `M`: known only to be some subtype of the erasure.
      const own = this.paramRef(b.overload.returnType, { owner: b.owner, overload: b.overload });
      if (own.varName && b.overload.typeParams.includes(own.varName)) return { ...own, inferred: true };
      returned = { text: b.overload.returnType, owner: b.owner };
      receiver = b.receiver;
    } else if (!b) {
      // An accessor that annotation processing writes: what it returns is the
      // field it reads.
      const recv = this.receiverTypeOf(inner, rec);
      receiver = recv?.kind === 'project' ? recv.fqn : inner.receiver === null ? this.enclosingTypeOf(inner, rec)?.fqn : undefined;
      if (receiver && inner.arguments.length === 0) returned = this.generatedGetterType(receiver, inner.method_name);
    }
    if (!returned) return null;
    const sub = this.substitute(returned.text, returned.owner, receiver);
    if (!sub) return null;
    const t = this.typeRef(sub.text, sub.rec);
    return t.typeVar ? null : t;
  }

  /**
   * The type a generated `getX()` / `isX()` returns on `fqn`: the written
   * type of field `x`, with the type that declares the field.
   */
  private generatedGetterType(fqn: string, method: string): { text: string; owner: TypeRecord } | undefined {
    const m = /^(get|is)([A-Z]\w*)$/.exec(method);
    const t = this.typesByFqn.get(fqn);
    if (!m || !t || !this.wouldBeGenerated(t, method)) return undefined;
    const field = m[2].charAt(0).toLowerCase() + m[2].slice(1);
    const seen = new Set<string>();
    const queue = [fqn];
    while (queue.length > 0) {
      const f = queue.shift()!;
      if (seen.has(f)) continue;
      seen.add(f);
      const ft = this.typesByFqn.get(f);
      const frec = ft ? this.files.get(ft.file) : undefined;
      if (!ft || !frec) continue;
      const type = ft.fieldTypes.get(field);
      if (type) return { text: type, owner: ft };
      for (const sup of ft.superNames) {
        const s = this.resolveTypeName(sup, frec);
        if (s) queue.push(s);
      }
    }
    return undefined;
  }

  /**
   * A member's written type as seen from a receiver of type `from`: a type
   * parameter of the declaring type is replaced by the argument the
   * superclass chain from `from` up to it supplies — `Loan extends
   * Base<Long>` makes `Base<T>.getId()`'s `T` a `Long`. Returns the text and
   * the file it must be resolved in, or nothing when a type parameter is
   * left unbound.
   */
  private substitute(
    written: string,
    owner: TypeRecord,
    from: string | undefined,
  ): { text: string; rec: FileRecord | undefined } | undefined {
    const ownRec = this.files.get(owner.file);
    const bare = eraseType(written).replace(/(\[\])+$/, '');
    if (!owner.typeParams.includes(bare)) return { text: written, rec: ownRec };
    if (!from || from === owner.fqn) return undefined;
    // Breadth-first up from `from`, carrying each type's parameter bindings.
    type Env = Map<string, { text: string; rec: FileRecord | undefined }>;
    const queue: Array<{ fqn: string; env: Env }> = [{ fqn: from, env: new Map() }];
    const seen = new Set<string>();
    while (queue.length > 0) {
      const { fqn, env } = queue.shift()!;
      if (fqn === owner.fqn) {
        const bound = env.get(bare);
        if (!bound) return undefined;
        const dims = written.slice(written.lastIndexOf(bare) + bare.length).match(/\[\]/g)?.length ?? 0;
        return { text: `${bound.text}${'[]'.repeat(dims)}`, rec: bound.rec };
      }
      if (seen.has(fqn)) continue;
      seen.add(fqn);
      const t = this.typesByFqn.get(fqn);
      const rec = t ? this.files.get(t.file) : undefined;
      if (!t || !rec) continue;
      for (const sup of t.superNames) {
        const supFqn = this.resolveTypeName(sup, rec);
        const st = supFqn ? this.typesByFqn.get(supFqn) : undefined;
        if (!st) continue;
        const open = sup.indexOf('<');
        const args = open === -1 ? [] : splitTopLevel(sup.slice(open + 1, sup.lastIndexOf('>'))).map(a => a.trim());
        const next: Env = new Map();
        st.typeParams.forEach((p, i) => {
          const a = args[i];
          if (!a) return;
          next.set(p, env.get(a) ?? { text: a, rec });
        });
        queue.push({ fqn: st.fqn, env: next });
      }
    }
    return undefined;
  }

  /** The outermost call named `name` that starts at `line:column` in `rec`. */
  private callAt(rec: FileRecord, line: number, column: number, name: string): CallInfo | undefined {
    let byPos = this.callsAt.get(rec.path);
    if (!byPos) {
      byPos = new Map();
      for (const c of rec.calls) push(byPos, `${c.location.line}:${c.location.column}`, c);
      this.callsAt.set(rec.path, byPos);
    }
    const here = (byPos.get(`${line}:${column}`) ?? []).filter(c => c.method_name === name);
    // `a.x().x()` puts two calls named `x` at one position; the outer one has
    // the longer receiver.
    return here.sort((x, y) => (y.receiver?.length ?? 0) - (x.receiver?.length ?? 0))[0];
  }

  /** A written type, resolved from one file's point of view. */
  private typeRef(written: string, rec: FileRecord | undefined): TypeRef {
    let t = written.replace(/@[\w.]+(\([^)]*\))?\s*/g, '').replace(/\bfinal\s+/g, '').trim();
    let dims = 0;
    if (t.endsWith('...')) { dims++; t = t.slice(0, -3).trim(); }
    t = eraseType(t);
    while (t.endsWith('[]')) { dims++; t = t.slice(0, -2).trim(); }
    const simple = t.split('.').pop() ?? t;
    if (PRIMITIVES.has(t)) return { simple: t, fqn: t, dims, prim: true, typeVar: false };
    if (t === 'null') return { simple: 'null', fqn: null, dims: 0, prim: false, typeVar: false };
    let fqn: string | null = null;
    if (t.includes('.')) {
      fqn = (rec ? this.resolveTypeName(t, rec) : undefined) ?? t;
    } else if (rec) {
      // An import names the type outright, ours or not. Failing that, a JDK
      // name is the JDK's unless this package declares its own — the tree-wide
      // unique-simple-name fallback must not turn `Date` into a project type.
      const imported = rec.imports.get(t);
      if (imported) fqn = imported;
      else if ((JAVA_LANG.has(t) || t in JDK_SUPERS) && !this.typesByFqn.has(rec.pkg ? `${rec.pkg}.${t}` : t)) fqn = null;
      else fqn = this.resolveTypeName(t, rec) ?? null;
    }
    if (!fqn && JAVA_LANG.has(t)) fqn = `java.lang.${t}`;
    const typeVar = !fqn && /^[A-Z][A-Z0-9]?$/.test(t);
    return { simple, fqn, dims, prim: false, typeVar };
  }

  /** Whether overload `o` of `owner` is what a query's parameter list names. */
  private signatureMatches(o: Overload, params: string[], owner: TypeRecord): boolean {
    if (o.params.length !== params.length) return false;
    const have = this.paramRefs({ owner, overload: o });
    return have.every((h, i) => {
      const want = this.typeRef(params[i], undefined);
      if (want.dims !== h.dims) return false;
      const wantBare = eraseType(params[i].replace(/\.\.\.$/, '').replace(/(\[\])+$/, ''));
      // A type variable is named as written (`K`) or by its erasure (`Object`,
      // `java.lang.Object`), the way the compiler and bytecode name it.
      if (h.varName && wantBare === h.varName) return true;
      return this.sameAsWritten(h, want, wantBare);
    });
  }

  /** Whether a declared parameter type is the one a query wrote. */
  private sameAsWritten(have: TypeRef, want: TypeRef, wantBare: string): boolean {
    if (wantBare.includes('.') && have.fqn && !have.prim) return have.fqn === wantBare;
    return have.simple === want.simple;
  }

  /**
   * Same name and same parameter types: one overrides the other, as the
   * compiler decides it. Within one type that is the erasure, which the
   * compiler requires to differ between two declarations. Between a type and
   * its supertype, the supertype's parameter types are first read through the
   * subtype's supertype clauses — `Fn<T>.apply(T)` is `apply(String)` to a
   * class implementing `Fn<String>`, and `apply(T)` to one implementing
   * `Fn<T>`, which then does not override it with `apply(Collection<T>)` —
   * and the erasures compared. Between types neither of which is known to
   * extend the other, a type variable still matches whatever its erasure
   * admits.
   */
  private sameErasure(a: Candidate, b: Candidate): boolean {
    if (a.overload.name !== b.overload.name || a.overload.params.length !== b.overload.params.length) return false;
    if (a.owner !== b.owner) {
      const sub = this.isSubtype(a.owner.fqn, b.owner.fqn) ? a : this.isSubtype(b.owner.fqn, a.owner.fqn) ? b : undefined;
      if (sub) return this.overridesBySubstitution(sub, sub === a ? b : a);
    }
    const pa = this.paramRefs(a);
    const pb = this.paramRefs(b);
    const across = a.owner !== b.owner;
    const open = (t: TypeRef, c: Candidate): boolean =>
      across && t.typeVar && (!t.varName || !c.overload.typeParams.includes(t.varName));
    return pa.every((x, i) => {
      const y = pb[i];
      if (x.dims !== y.dims) return false;
      const xo = open(x, a);
      const yo = open(y, b);
      if (xo && yo) return true;
      if (xo) return !x.erasure || this.fits({ ...y, dims: 0 }, { ...x.erasure, dims: 0 }, 1) !== 'no';
      if (yo) return !y.erasure || this.fits({ ...x, dims: 0 }, { ...y.erasure, dims: 0 }, 1) !== 'no';
      // A type variable no declaration in scope names: as lenient as before.
      if ((x.typeVar && !x.erasure) || (y.typeVar && !y.erasure)) return true;
      return x.simple === y.simple;
    });
  }

  /** Whether `sub`'s declaration has `sup`'s parameter types as `sub`'s type sees them, erased. */
  private overridesBySubstitution(sub: Candidate, sup: Candidate): boolean {
    const mine = this.paramRefs(sub);
    const scope = this.scopeOf(sub.owner, sub.overload);
    return sup.overload.params.every((written, i) => {
      const own = sup.overload.vars[i];
      // The supertype method's own type variable: its erasure.
      const s = own && sup.overload.typeParams.includes(own.name) ? undefined : this.substitute(written, sup.owner, sub.owner.fqn);
      // No binding read for the variable (a raw supertype, or a clause this
      // index cannot resolve): the supertype's own erasure.
      const theirs = s
        ? this.withErasure(s.text, eraseWritten(s.text, scope), s.rec)
        : this.paramRef(written, sup);
      const m = mine[i];
      if (m.dims !== theirs.dims) return false;
      if (m.typeVar && !m.erasure) return true;
      if (theirs.typeVar && !theirs.erasure) return true;
      return m.simple === theirs.simple;
    });
  }

  /** A candidate's parameter types, each type variable carrying its erasure. */
  private paramRefs(c: Candidate): TypeRef[] {
    return c.overload.params.map(p => this.paramRef(p, c));
  }

  /**
   * `c`'s parameter types as a call on `self` — the enclosing type, as an
   * implicit, `this.` or `super.` receiver — sees them: a variable of the
   * declaring type is that of `self` when `self` declares it, and what
   * `self`'s supertype clauses fill it with when it is inherited
   * (`Lru extends Base<String>` makes `Base<K>.put(K)` a `put(String)`).
   */
  private paramRefsFrom(c: Candidate, self: TypeRecord | undefined): TypeRef[] {
    const refs = this.paramRefs(c);
    if (!self) return refs;
    return refs.map((r, i) => {
      if (!r.typeVar || !r.varName || c.overload.typeParams.includes(r.varName)) return r;
      if (c.owner === self) return { ...r, opaque: true };
      const sub = this.substitute(c.overload.params[i], c.owner, self.fqn);
      if (!sub) return r;
      const e = eraseWritten(sub.text, this.scopeOf(self, undefined));
      if (e) return { ...this.withErasure(sub.text, e, sub.rec), opaque: true };
      return this.typeRef(sub.text, sub.rec);
    });
  }

  /**
   * An argument's written type at a call site: a type variable of the
   * enclosing method or type carries its erasure.
   */
  private callSiteRef(written: string, call: CallInfo, rec: FileRecord): TypeRef {
    const encl = this.enclosingTypeOf(call, rec);
    if (!encl) return this.typeRef(written, rec);
    const line = call.location.line;
    let method: Overload | undefined;
    for (const list of encl.overloads.values()) {
      for (const o of list) {
        if (line < o.startLine || line > o.endLine) continue;
        if (!method || o.endLine - o.startLine < method.endLine - method.startLine) method = o;
      }
    }
    return this.withErasure(written, eraseWritten(written, this.scopeOf(encl, method)), rec);
  }

  /** One written parameter (or return) type of `c`, from its declaring file's point of view. */
  private paramRef(written: string, c: Candidate): TypeRef {
    const i = c.overload.params.indexOf(written);
    const e = i !== -1 && c.overload.vars[i]
      ? { ...c.overload.vars[i]!, text: c.overload.erased[i] }
      : eraseWritten(written, this.scopeOf(c.owner, c.overload));
    return this.withErasure(written, e, this.files.get(c.owner.file));
  }

  /** A written type, with the erasure `eraseWritten` found for it when it is a type variable. */
  private withErasure(
    written: string,
    e: { name: string; text: string; certain: boolean } | undefined,
    rec: FileRecord | undefined,
  ): TypeRef {
    if (!e) return this.typeRef(written, rec);
    const erased = this.typeRef(e.text, rec);
    return { ...erased, typeVar: true, varName: e.name, erasure: erased, certain: e.certain };
  }

  /** The type variables visible in a member of `owner` (`overload`), innermost first. */
  private scopeOf(owner: TypeRecord, overload: Overload | undefined): VarScope {
    const types: TypeRecord[] = [];
    let t: TypeRecord | undefined = owner;
    while (t) {
      types.push(t);
      const outer = this.typesByFqn.get(stripLast(t.fqn));
      t = outer && outer.file === owner.file ? outer : undefined;
    }
    return { method: overload ?? null, types };
  }

  // --------------------------------------------------------------- dispatch

  /**
   * How a site bound to `owner.overload` reaches `target`'s overload, if it
   * does: through a supertype's declaration the target overrides, or by
   * calling an override of the target.
   */
  private dispatchRelation(
    owner: TypeRecord,
    overload: Overload,
    receiver: string | undefined,
    target: TypeRecord,
    wanted: Overload[],
  ): { relation: 'supertype' | 'override'; overload: Overload } | undefined {
    if (owner === target || overload.isConstructor || overload.modifiers.includes('static')) return undefined;
    for (const w of wanted) {
      if (w.modifiers.includes('static') || w.modifiers.includes('private')) continue;
      if (!this.sameErasure({ owner, overload }, { owner: target, overload: w })) continue;
      if (this.isSubtype(target.fqn, owner.fqn)) {
        // The receiver's static type must admit the target's type, or the
        // object can never be one: a sibling's call does not land here.
        if (!receiver || this.isSubtype(target.fqn, receiver)) return { relation: 'supertype', overload: w };
      } else if (this.isSubtype(owner.fqn, target.fqn)) {
        return { relation: 'override', overload: w };
      }
    }
    return undefined;
  }

  /** Whether calls to `o` on `t` can dispatch anywhere but `t`'s own body. */
  private dispatchIsOpen(t: TypeRecord, o: Overload): boolean {
    if (o.isConstructor || o.modifiers.includes('static') || o.modifiers.includes('private')) return false;
    if (this.isBodyless(t, o)) return true;
    const self: Candidate = { owner: t, overload: o };
    // Not `visibleOverloads`: it leaves out exactly the declarations an
    // override hides, which are the ones that make dispatch open.
    const declaresAbove = (f: string, seen: Set<string>): boolean => {
      if (seen.has(f)) return false;
      seen.add(f);
      const st = this.typesByFqn.get(f);
      const rec = st ? this.files.get(st.file) : undefined;
      if (!st || !rec) return false;
      if (st !== t && (st.overloads.get(o.name) ?? []).some(x => this.sameErasure({ owner: st, overload: x }, self))) return true;
      return st.superNames.some(sup => {
        const s = this.resolveTypeName(sup, rec);
        return s !== undefined && declaresAbove(s, seen);
      });
    };
    if (declaresAbove(t.fqn, new Set())) return true;
    const seen = new Set<string>();
    const below = (f: string): boolean => {
      for (const sub of this.subtypes.get(f) ?? []) {
        if (seen.has(sub)) continue;
        seen.add(sub);
        const st = this.typesByFqn.get(sub);
        if (st && (st.overloads.get(o.name) ?? []).some(x => this.sameErasure({ owner: st, overload: x }, self))) return true;
        if (below(sub)) return true;
      }
      return false;
    };
    return below(t.fqn);
  }

  /** `a` is `b` or a subtype of it, by the edges the tree holds. */
  private isSubtype(a: string, b: string): boolean {
    if (a === b) return true;
    const seen = new Set<string>();
    const walk = (f: string): boolean => {
      if (seen.has(f)) return false;
      seen.add(f);
      const t = this.typesByFqn.get(f);
      const rec = t ? this.files.get(t.file) : undefined;
      if (!t || !rec) return false;
      for (const sup of t.superNames) {
        const s = this.resolveTypeName(sup, rec);
        if (!s) continue;
        if (s === b || walk(s)) return true;
      }
      return false;
    };
    return walk(a);
  }

  /** The query's scope, with what dispatch it cannot see said out loud. */
  private dispatchScope(symbol: string): Scope {
    return {
      searched: this.scope.searched,
      excluded: [
        ...this.scope.excluded,
        {
          pattern: 'subtypes outside the searched tree',
          reason: `dispatch: an override of ${symbol}, or a call through a supertype, in a library or module not indexed here is not seen`,
        },
        {
          pattern: 'reflection',
          reason: 'dynamic: Method.invoke, proxies and method handles are not followed',
        },
        {
          pattern: 'framework dispatch',
          reason: 'a framework that invokes a method by annotation, configuration or naming convention leaves no call site to answer',
        },
      ],
    };
  }

  // ---------------------------------------------------------- receiver type

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
   * chain is not a type. So does a step whose overloads of that arity
   * disagree on what they return.
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
    let evidence: string;

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
      const returnType = owner ? this.returnTypeAt(owner.fqn, root.name, root.argc) : undefined;
      if (!owner || !returnType) return undefined;
      current = this.resolveTypeRecord(returnType, rec);
      if (!current) return undefined;
      evidence = `chain rooted at ${owner.fqn}.${root.name}, which returns ${returnType}`;
    }

    for (const step of chain.steps) {
      const returnType = this.returnTypeAt(current.fqn, step.name, step.argc);
      if (!returnType) return undefined;
      const next = this.resolveTypeRecord(returnType, rec);
      if (!next) return undefined;
      evidence += ` → ${step.name}() returns ${returnType}`;
      current = next;
    }
    return { kind: 'project', fqn: current.fqn, evidence };
  }

  /**
   * The return type of `name` called with `argc` arguments on `fqn`, when
   * every overload of that arity agrees on it.
   */
  private returnTypeAt(fqn: string, name: string, argc: number): string | undefined {
    const cands = this.visibleOverloads(fqn, name).filter(c => fitsArity(c.overload, argc));
    const types = new Set(cands.map(c => c.overload.returnType));
    if (types.size !== 1) return undefined;
    return [...types][0] ?? undefined;
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

  /** The method whose body holds `line`, with a parameter list when its name is overloaded. */
  private methodAt(rec: FileRecord, line: number): string | undefined {
    const t = this.enclosingTypeAt(rec, line);
    if (!t) return undefined;
    for (const [name, list] of t.overloads) {
      for (const o of list) {
        if (line < o.startLine || line > o.endLine) continue;
        const member = o.isConstructor ? `${t.fqn}.<init>` : `${t.fqn}.${name}`;
        return list.length > 1 ? `${member}${signatureOf(o)}` : member;
      }
    }
    return undefined;
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

  /**
   * Whether a declaration carries no body, so nothing it names can run.
   *
   * A class method says so itself: `abstract` is in its modifiers. An
   * interface method does not — the Java extraction reports no modifiers for
   * either an abstract member or a `default` one — so the declaration line is
   * read from the source, where `default` and `static` are the only two ways
   * an interface member can have a body. `default` and `static` precede the
   * return type, so they are on the declaration's first line.
   *
   * With no source supplied, an interface member is treated as body-less.
   * That is the conservative direction: it costs an answer its `exact` label
   * and never grants one.
   */
  private isBodyless(owner: TypeRecord, o: Overload): boolean {
    if (o.modifiers.includes('abstract')) return true;
    if (owner.kind !== 'interface') return false;
    if (o.modifiers.includes('static') || o.modifiers.includes('default')) return false;
    const line = this.files.get(owner.file)?.lines?.[o.startLine - 1];
    if (line === undefined) return true;
    return !/\b(default|static)\b/.test(line);
  }

  /**
   * Types in the tree that declare a **runnable** override of `o` and are
   * `fqn` or below it.
   *
   * "Runnable" is the whole of it: `candidates` answers "which body could
   * run", so an abstract declaration does not belong there even when it is
   * the type the walk started from. An `abstract class Base { abstract step(); }`
   * with nothing overriding `step` has no candidates, and saying so is the
   * honest answer — listing `Base.step` would name a body that does not exist.
   */
  private implementorsWith(fqn: string, o: Overload): string[] {
    const out: string[] = [];
    const start = this.typesByFqn.get(fqn);
    const self: Candidate | undefined = start ? { owner: start, overload: o } : undefined;
    const walk = (f: string, seen: Set<string>): void => {
      if (seen.has(f)) return;
      seen.add(f);
      const t = this.typesByFqn.get(f);
      if (t && t.kind !== 'interface' && self) {
        const own = (t.overloads.get(o.name) ?? []).find(x => !x.isConstructor && this.sameErasure({ owner: t, overload: x }, self));
        if (own && !this.isBodyless(t, own)) out.push(f);
      }
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
  private nameCouldMatch(call: CallInfo, wantedName: string, owner: string): boolean {
    if (wantedName === '<init>') {
      const t = this.typesByFqn.get(owner);
      return !!t && (call.is_constructor === true || call.method_name === t.simpleName);
    }
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
      return this.symbolOfCall(call, rec);
    }
    return this.methodAt(rec, query.site.line);
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
    extra: Pick<NavigationAnswer, 'note' | 'overloads'> = {},
    scope: Scope = this.scope,
  ): NavigationAnswer {
    let kept = answers;
    if (opts.tiers) kept = kept.filter(a => opts.tiers!.includes(a.tier));
    // Answers to an overloaded method arrive grouped per overload; the order
    // of the groups is the order of `overloads`, i.e. of declaration.
    const group = new Map((extra.overloads ?? []).map((o, i) => [o.signature, i]));
    kept = [...kept].sort(
      (a, b) =>
        (group.get(a.signature ?? '') ?? 0) - (group.get(b.signature ?? '') ?? 0) ||
        a.site.file.localeCompare(b.site.file) ||
        a.site.line - b.site.line,
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
      scope,
      timing: {
        parseMs: round(this.parseMs),
        indexMs: round(this.indexMs),
        queryMs: round(now() - t0),
      },
    };
    if (truncated) out.truncated = truncated;
    if (extra.overloads) out.overloads = extra.overloads;
    if (extra.note) out.note = extra.note;
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
    const methods = new Map<string, { returnType: string | null; startLine: number; endLine: number; modifiers: string[] }>();
    const overloads = new Map<string, Overload[]>();
    for (const m of t.methods ?? []) {
      // A later overload does not replace an earlier one's range; the widest
      // range wins, so a callee query over the method's body sees all of it.
      const prev = methods.get(m.name);
      methods.set(m.name, {
        returnType: m.return_type ?? prev?.returnType ?? null,
        startLine: prev ? Math.min(prev.startLine, m.start_line) : m.start_line,
        endLine: prev ? Math.max(prev.endLine, m.end_line) : m.end_line,
        modifiers: [...new Set([...(prev?.modifiers ?? []), ...(m.modifiers ?? [])])],
      });
      const params = (m.parameters ?? []).map(p => p.type ?? '?');
      // The extraction reports a constructor's return type as `null` and a
      // method's as at least `void`; a constructor is named after its type.
      const isConstructor = m.return_type === null && m.name === t.name;
      push(overloads, m.name, {
        name: m.name,
        params,
        varargs: params.length > 0 && params[params.length - 1].endsWith('...'),
        returnType: m.return_type ?? null,
        isConstructor,
        startLine: m.start_line,
        endLine: m.end_line,
        modifiers: m.modifiers ?? [],
        typeParams: m.type_parameters ?? [],
        typeBounds: m.type_parameter_bounds ?? {},
        erased: params,
        vars: params.map(() => null),
      });
    }
    types.push({
      fqn: path,
      simpleName: t.name,
      kind: t.kind,
      isRecord: t.is_record === true,
      file: f.path,
      superNames: [t.extends, ...(t.implements ?? [])].filter((x): x is string => !!x),
      extendsName: t.extends ?? null,
      annotations: (t.annotations ?? []).map(stripAnnotation),
      fieldNames: (t.fields ?? []).map(x => x.name),
      fieldTypes: new Map((t.fields ?? []).filter(x => x.type).map(x => [x.name, x.type!])),
      typeParams: t.type_parameters ?? [],
      typeBounds: t.type_parameter_bounds ?? {},
      getterFields: lombokFields(f.source, 'Getter'),
      setterFields: lombokFields(f.source, 'Setter'),
      methods,
      overloads,
      startLine: t.start_line,
      endLine: t.end_line,
    });
  }

  // Erase each parameter's type variables. Everything a declaration's
  // variables can name — the method, its type, the types enclosing it — is in
  // this file, so the result is per file and cached with it.
  for (const t of types) {
    const chain: TypeRecord[] = [];
    for (let c: TypeRecord | undefined = t; c; c = types.find(x => x.fqn === stripLast(c!.fqn))) chain.push(c);
    for (const list of t.overloads.values()) {
      for (const o of list) {
        const scope: VarScope = { method: o, types: chain };
        const es = o.params.map(p => eraseWritten(p, scope));
        o.erased = o.params.map((p, i) => es[i]?.text ?? p);
        o.vars = es.map(e => (e ? { name: e.name, certain: e.certain } : null));
      }
    }
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

/** `pkg.Type.method(A,B)` → its parts. The parameter list may hold generics with commas. */
function parseSymbol(symbol: string): ParsedSymbol {
  const open = symbol.indexOf('(');
  const base = (open === -1 ? symbol : symbol.slice(0, open)).trim();
  const out: ParsedSymbol = { base, owner: stripLast(base), name: lastSegment(base) };
  if (open !== -1) {
    const close = symbol.lastIndexOf(')');
    out.params = splitTopLevel(symbol.slice(open + 1, close === -1 ? undefined : close))
      .map(p => p.trim())
      .filter(Boolean);
  }
  return out;
}

/** Split on commas outside `<...>`. */
function splitTopLevel(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let buf = '';
  for (const ch of text) {
    if (ch === '<') depth++;
    if (ch === '>') depth--;
    if (ch === ',' && depth === 0) { out.push(buf); buf = ''; continue; }
    buf += ch;
  }
  out.push(buf);
  return out;
}

/**
 * `(Long,String)` — simple names, generics erased, `String...` for varargs, a
 * type variable shown as its erasure: `getNumber(Map,Object)` for
 * `<K> getNumber(Map<? super K, ?>, K)`, as javadoc and bytecode name it.
 */
function signatureOf(o: Overload): string {
  return `(${o.erased.map(p => {
    const varargs = p.endsWith('...');
    let t = eraseType(p.replace(/@[\w.]+(\([^)]*\))?\s*/g, '').replace(/\bfinal\s+/g, '').replace(/\.\.\.$/, '').trim());
    let dims = '';
    while (t.endsWith('[]')) { dims += '[]'; t = t.slice(0, -2).trim(); }
    return `${t.split('.').pop() ?? t}${dims}${varargs ? '...' : ''}`;
  }).join(',')})`;
}

/** `pkg.Type.method`, or `pkg.Type.<init>` for a constructor. */
function memberName(owner: TypeRecord, o: Overload): string {
  return o.isConstructor ? `${owner.fqn}.<init>` : `${owner.fqn}.${o.name}`;
}

/** The type variables in scope at a declaration: the method's own, then each type's from the innermost out. */
interface VarScope {
  method: { typeParams: string[]; typeBounds: Record<string, string> } | null;
  types: Array<{ typeParams: string[]; typeBounds: Record<string, string> }>;
}

/**
 * What a written type that is a type variable erases to, the way the compiler
 * erases it: its leftmost bound, erased in turn when the bound is itself a
 * variable (`W extends U`), else `Object`; array and varargs suffixes kept.
 * Nothing when it is not a type variable in scope. The innermost declaration
 * of a name hides the outer ones.
 *
 * `certain` says whether an argument that fits the erasure certainly fits the
 * variable: so for a method's own variable, which the compiler infers from
 * the arguments, unless its bound names the variable itself
 * (`T extends Comparable<T>`); never for a type's, which the receiver fixes.
 */
function eraseWritten(
  written: string,
  scope: VarScope,
  seen: Set<string> = new Set(),
): { name: string; text: string; certain: boolean } | undefined {
  let t = written.replace(/@[\w.]+(\([^)]*\))?\s*/g, '').replace(/\bfinal\s+/g, '').trim();
  let suffix = '';
  if (t.endsWith('...')) { suffix = '...'; t = t.slice(0, -3).trim(); }
  t = eraseType(t);
  while (t.endsWith('[]')) { suffix = `[]${suffix}`; t = t.slice(0, -2).trim(); }
  if (!/^[A-Za-z_$][\w$]*$/.test(t) || seen.has(t)) return undefined;
  let v: { bound: string | null; kind: 'method' | 'type' } | undefined;
  if (scope.method?.typeParams.includes(t)) v = { bound: scope.method.typeBounds[t] ?? null, kind: 'method' };
  else {
    const owner = scope.types.find(x => x.typeParams.includes(t));
    if (owner) v = { bound: owner.typeBounds[t] ?? null, kind: 'type' };
  }
  if (!v) return undefined;
  if (v.bound === null) return { name: t, text: `Object${suffix}`, certain: v.kind === 'method' };
  const inner = eraseWritten(v.bound, scope, new Set([...seen, t]));
  if (inner) return { name: t, text: `${inner.text}${suffix}`, certain: v.kind === 'method' && inner.certain };
  const args = v.bound.includes('<') ? v.bound.slice(v.bound.indexOf('<') + 1) : '';
  const selfBounded = new RegExp(`\\b${t}\\b`).test(args);
  return { name: t, text: `${eraseType(v.bound)}${suffix}`, certain: v.kind === 'method' && !selfBounded };
}

/** Remove every `<...>` from a written type. */
function eraseType(t: string): string {
  let out = '';
  let depth = 0;
  for (const ch of t) {
    if (ch === '<') { depth++; continue; }
    if (ch === '>') { depth--; continue; }
    if (depth === 0) out += ch;
  }
  return out.trim();
}

/** A varargs parameter's element type. */
function elementOf(t: TypeRef): TypeRef {
  const dims = Math.max(0, t.dims - 1);
  return { ...t, dims, ...(t.erasure ? { erasure: { ...t.erasure, dims } } : {}) };
}

/** Whether a call with `n` arguments can reach overload `o` at all. */
function fitsArity(o: Overload, n: number): boolean {
  if (o.params.length === n) return true;
  return o.varargs && n >= o.params.length - 1;
}

/**
 * The name of the outermost call an expression is, or nothing when it is not
 * a call: `a.b(x).c(y)` → `c`, `make(x)` → `make`, `a.<T>m()` → `m`.
 */
function outerCallName(expr: string): string | undefined {
  const text = expr.trim();
  if (!text.endsWith(')')) return undefined;
  let depth = 0;
  let open = -1;
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i];
    if (ch === ')') depth++;
    else if (ch === '(') {
      depth--;
      if (depth === 0) { open = i; break; }
    }
  }
  if (open <= 0) return undefined;
  const m = /([A-Za-z_$][\w$]*)\s*$/.exec(text.slice(0, open));
  if (!m) return undefined;
  const before = text.slice(0, open - m[0].length).trimEnd();
  // `new Foo(…)` is a constructor, typed by the extractor, not here.
  if (/\bnew$/.test(before)) return undefined;
  return m[1];
}

/** Top-level arguments in an argument list's text, counted. */
function countArgs(argText: string): number {
  if (argText.trim() === '') return 0;
  let depth = 0;
  let quote: string | null = null;
  let n = 1;
  for (let i = 0; i < argText.length; i++) {
    const ch = argText[i];
    if (quote) {
      if (ch === quote && argText[i - 1] !== '\\') quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{' || ch === '<') depth++;
    else if (ch === ')' || ch === ']' || ch === '}' || ch === '>') depth--;
    else if (ch === ',' && depth === 0) n++;
  }
  return n;
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
): {
  root: { kind: 'type' | 'this' | 'call'; name: string; argc: number };
  steps: Array<{ name: string; line: number; argc: number }>;
} | null {
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

  const argcOf = (p: string): number => {
    const open = p.indexOf('(');
    const close = p.lastIndexOf(')');
    return open === -1 || close < open ? 0 : countArgs(p.slice(open + 1, close));
  };
  const head = parts[0].trim();
  let root: { kind: 'type' | 'this' | 'call'; name: string; argc: number };
  if (head === 'this') root = { kind: 'this', name: 'this', argc: 0 };
  else if (/^[A-Z]\w*$/.test(head)) root = { kind: 'type', name: head, argc: 0 };
  else if (/^[a-zA-Z_]\w*\s*\(/.test(head)) root = { kind: 'call', name: head.slice(0, head.indexOf('(')).trim(), argc: argcOf(head) };
  else return null;   // a plain identifier, an index, an expression — not typed here

  const steps: Array<{ name: string; line: number; argc: number }> = [];
  for (const raw of parts.slice(1)) {
    const p = raw.trim();
    const m = /^([a-zA-Z_]\w*)\s*\(/.exec(p);
    if (!m) return null;   // a field access mid-chain is not walked
    steps.push({ name: m[1], line: 0, argc: argcOf(p) });
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
