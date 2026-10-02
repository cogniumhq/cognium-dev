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
 *   hierarchy slice. Nothing else may carry this label.
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
  /** The file did not parse cleanly, so the site's context is incomplete. */
  | 'parse-error'
  /** The site is in a language this index does not parse. */
  | 'unsupported-language'
  /** None of the above, including a target in the tree that could not be bound. */
  | 'unknown';

export interface AnswerEntry {
  /** Fully-qualified name of the target. A constructor is `<Type>.<init>`. */
  target: string;
  tier: Tier;
  /** Every implementor found, on `polymorphic`. */
  candidates?: string[];
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

/** A query names either a symbol or a site; never both. */
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
}

export interface QueryOptions {
  /** Cap on `answers`; the cut is reported in `truncated`. */
  limit?: number;
  /** Tiers to return. Default: all three. */
  tiers?: Tier[];
}
