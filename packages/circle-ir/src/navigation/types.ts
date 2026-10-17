/**
 * The answer shape for the navigation queries.
 *
 * This shape is a contract, not an internal convenience: it is fixed field for
 * field by the evaluation pack that grades these answers, and the controls read
 * nothing else. Three of its fields exist only so that an answer can be judged
 * rather than believed:
 *
 *   - `tier` says how the target was reached, and `exact` is a promise (below).
 *   - `unresolved[].reason` says why a site in range produced no answer, drawn
 *     from a closed vocabulary. An unreasoned non-answer is a deviation.
 *   - `scope` states the denominator. A precision figure without the set it
 *     was measured over is not a result, so every answer carries what was
 *     searched and what was deliberately left out.
 */

/**
 * A single call site, as every answer and every non-answer refers to one.
 *
 * `file` / `line` / `col` / `text` are the pack's site shape, field for field.
 * `inMethod` is an addition, and the only field here beyond that shape: an
 * agent reading "47 callers" wants to know which methods they are in without
 * opening 47 files, and the IR already knows. A control that reads only the
 * four named fields is unaffected by it.
 *
 * **A site is not a unique key.** A chained expression reports several calls at
 * one line and column — `Builder.of().step("a").done()` yields three, all at
 * the start of the expression — so a (file, line, col) triple can name more
 * than one call. Anything that needs to address one call must carry the method
 * name too.
 */
export interface CallSite {
  file: string;
  line: number;
  /** 0-indexed, as tree-sitter reports it. */
  col: number;
  /** The source line, trimmed. Present when the index was given the source. */
  text?: string;
  /** The enclosing method's simple name, where the IR knows it. An addition. */
  inMethod?: string | null;
}

/**
 * How the target was reached.
 *
 * - `exact` — **a promise.** The receiver's static type is known to the
 *   resolver and the target is the unique method of that name in that type's
 *   hierarchy slice — or, where the name is overloaded, the one overload the
 *   call's arity and argument types admit. Nothing else may carry this label.
 * - `polymorphic` — the receiver's type is known and dispatch is open; every
 *   implementor found is in `candidates`.
 * - `inferred` — bound by name alone, with no receiver type to confirm it.
 *   **A permanent floor.** Measured on a 405-file Java repository, a name-only
 *   bind was contradicted by the resolver's own receiver type on 78 of 147
 *   claims for one method, so an `inferred` answer is reported, labelled, and
 *   never counted as a caller. It is never promoted to `exact` — what earns
 *   `exact` is knowing the receiver's type, not growing confident about a name.
 */
export type Tier = 'exact' | 'polymorphic' | 'inferred';

/** Why a site in range produced no answer. A closed vocabulary. */
export type UnresolvedReason =
  /** The target is declared outside the searched tree — JDK, framework, library. */
  | 'external'
  /** Reflective or otherwise runtime-determined dispatch. */
  | 'dynamic'
  /** The target exists only after annotation processing or code generation. */
  | 'generated'
  /**
   * The site calls a method of the target's name on the target's type, and
   * more than one overload could be the one it calls. Not an answer: the
   * candidate signatures are in `candidates`, and choosing one would be a guess.
   */
  | 'overload-ambiguous'
  /** The file did not parse cleanly, so the site's context is incomplete. */
  | 'parse-error'
  /** The site is in a language this index does not parse. */
  | 'unsupported-language'
  /** None of the above, including a target in the tree that could not be bound. */
  | 'unknown';

export interface AnswerEntry {
  /**
   * Fully-qualified name of the target. A constructor is `<Type>.<init>`.
   *
   * On `polymorphic` this is the **declaring** member — the one the receiver's
   * static type resolves to, which for an interface-typed receiver is the
   * interface's member, not an implementation. `candidates` holds the bodies
   * that could run.
   */
  target: string;
  tier: Tier;
  /**
   * The bodies that could run, on `polymorphic`. Implementations only: the
   * declaring member is in `target`, and an interface's declaration is not a
   * body, so listing it here would be a candidate that cannot be reached.
   */
  candidates?: string[];
  /**
   * The parameter list of the overload this site calls, as `(Long,String)` —
   * simple type names, `String...` for varargs. Present only when the target's
   * type declares more than one method of that name; pass it back as
   * `Type.method(Long,String)` to ask about one overload alone.
   */
  signature?: string;
  /**
   * Set when the site does not bind to `target` itself but reaches it through
   * dispatch. `member` is what the site binds to statically.
   *
   * - `supertype` — the site calls a supertype's or interface's declaration
   *   that `target` overrides, through a receiver whose static type `target`'s
   *   type is a subtype of. At run time it lands on `target` when the object
   *   is of that type.
   * - `override` — the site calls a method that overrides or implements
   *   `target`. It reaches `target`'s body only through `super`, but it is a
   *   caller of the operation `target` declares, which is what a question
   *   about an abstract or interface method is usually asking.
   *
   * Always `polymorphic`: which body runs is decided at run time.
   */
  via?: { member: string; relation: 'supertype' | 'override' };
  /**
   * The method name as written at the call site.
   *
   * It is not always `target`'s last segment and cannot be derived from it: a
   * constructor's target ends `.<init>` while the call is written as the type
   * name. It is the third part of the only sound key for a call site —
   * `(file, line, methodName)` — because a chained expression reports several
   * calls at one line and column. `unresolved[].methodName` is the same field
   * for the same reason.
   */
  methodName: string;
  /** How the tier was arrived at, in one readable line. */
  evidence?: string;
  /** The call site this answer is about. */
  site: CallSite;
}

export interface UnresolvedEntry {
  site: CallSite;
  reason: UnresolvedReason;
  /** The method name the site called, which the reason alone does not say. */
  methodName?: string;
  /**
   * On `overload-ambiguous`: every overload the site could be calling, as
   * `pkg.Type.method(Long,String)`.
   */
  candidates?: string[];
}

export interface Scope {
  searched: {
    files: number;
    languages: string[];
  };
  /** What was deliberately left out, each with the reason it was. */
  excluded: Array<{ pattern: string; reason: string }>;
}

export interface Timing {
  parseMs: number;
  indexMs: number;
  queryMs: number;
}

export type QueryKind = 'callers' | 'callees';

/**
 * A query names either a symbol or a site; never both.
 *
 * A symbol is `pkg.Type.method`, optionally with a parameter list —
 * `pkg.Type.method(Long,String)`, simple or qualified type names, `()` for
 * none, `String...` or `String[]` for varargs — which narrows the query to one
 * overload. A constructor is `pkg.Type.<init>`, with the same optional list.
 */
export type Query =
  | { symbol: string; site?: never }
  | { site: CallSite; symbol?: never };

export interface NavigationAnswer {
  query: { kind: QueryKind; symbol?: string; site?: CallSite };
  answers: AnswerEntry[];
  unresolved: UnresolvedEntry[];
  scope: Scope;
  timing: Timing;
  /**
   * Set when `answers` was cut to `opts.limit`. A truncated list that does not
   * say so is a wrong denominator, which is worse than a short answer.
   */
  truncated?: { returned: number; total: number };
  /**
   * Set when the queried method is overloaded and the query named no
   * signature: every overload, with how many answers it has. `answers` is
   * grouped the same way, each entry carrying its `signature`. Overloads are
   * never merged silently.
   */
  overloads?: Array<{ signature: string; answers: number }>;
  /** One line a reader must not miss — "3 overloads; pass a signature to narrow". */
  note?: string;
}

export interface QueryOptions {
  /** Cap on `answers`; the cut is reported in `truncated`. */
  limit?: number;
  /** Tiers to return. Default: all three. */
  tiers?: Tier[];
}
