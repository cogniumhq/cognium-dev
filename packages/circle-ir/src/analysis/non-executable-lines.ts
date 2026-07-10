/**
 * Non-executable source-line gate.
 *
 * Defensive utility for circle-ir + downstream consumers (cognium-ai).
 * A "source" whose line number points at an import, package, comment,
 * annotation-only line, or a compile-time constant declaration cannot
 * legitimately host a runtime taint source — no HTTP parameter, cookie,
 * DB read, or user-controlled variable can be introduced by such a
 * line. When we see one, it is either:
 *
 *   1. an LLM enrichment hallucination (cognium-dev#250 root cause) —
 *      circle-ir-ai's `discoverSourcesForLanguage` step occasionally
 *      returns fabricated `additionalSources` at the top of the file,
 *   2. a static-detector regression that resolved a source line to a
 *      wrong AST node, or
 *   3. a caller bug — some external consumer passed a synthetic
 *      TaintSource with an obviously-wrong line.
 *
 * In all three cases, dropping the source is correct: any resulting
 * finding is a fabricated flow that would fail human review anyway.
 *
 * This module is intentionally regex-only (no AST dependency) so it can
 * run at any pipeline stage — including after enrichment, before finding
 * emission — and is fast enough to invoke per-source without measurable
 * overhead.
 */

/**
 * Return true when the given 1-based line number in `sourceCode` cannot
 * host a runtime taint source under the given language.
 *
 * Returns false (permissive) when:
 *   - `line` is out of range (defensive; callers should already have valid lines)
 *   - the language is unrecognized
 *   - the line's content genuinely looks executable
 */
export function isNonExecutableSourceLine(
  sourceCode: string,
  line: number,
  language: string,
): boolean {
  if (!sourceCode || line < 1) return false;
  const lines = sourceCode.split('\n');
  if (line > lines.length) return false;
  const raw = lines[line - 1] ?? '';
  const trimmed = raw.trim();
  if (trimmed === '') return true; // blank line

  const lang = language.toLowerCase();

  // ── universal comment forms (all supported languages allow at least one)
  //
  // Match anything that begins with a comment marker. Block-comment
  // interiors (`* text` continuation, `*/` closer) are treated as
  // non-executable in Java/JS/TS/Go/Rust/C-family syntaxes.
  if (
    trimmed.startsWith('//') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('*/') ||
    trimmed.startsWith('*') ||
    trimmed === '/**'
  ) {
    // In Python this would be misparsed (Python has no `//`), but a Python
    // line starting with `//` is either syntactically invalid or inside a
    // string — both fine to conservatively suppress.
    return true;
  }

  switch (lang) {
    case 'java':
    case 'javascript':
    case 'typescript':
    case 'go':
    case 'rust':
      return isNonExecutableCurly(trimmed);
    case 'python':
      return isNonExecutablePython(trimmed);
    default:
      return false;
  }
}

/**
 * Java / JavaScript / TypeScript / Go / Rust: shared brace-based
 * grammar for imports, package/module declarations, annotations,
 * and simple constant declarations.
 */
function isNonExecutableCurly(trimmed: string): boolean {
  // import / package / use / from … (Java, JS/TS ESM, Go, Rust)
  if (/^(import|package|use|from)\s/.test(trimmed)) return true;

  // Annotation-only line (Java `@Foo`, TS decorator `@Foo`).
  // Bare `@Foo` or `@Foo(...)` with no code after — e.g. the annotation
  // sits on its own line before the method/field it decorates.
  if (/^@[A-Za-z_][\w.]*(?:\s*\([^)]*\))?\s*$/.test(trimmed)) return true;

  // Compile-time constant declaration with pure string/number literal
  // RHS. LLM hallucinations often land on these because they look
  // "field-like" but the value cannot be tainted.
  //
  // Java:  private static final String X = "abc";
  // TS:    const X = "abc";
  // Go:    const X = "abc"; / const X string = "abc"
  // Rust:  const X: &str = "abc"; / static X: &str = "abc";
  //
  // Only literal RHS qualifies — an assignment from a function call or
  // identifier is executable and may legitimately be a source.
  if (
    /^(?:(?:public|private|protected|internal)\s+)?(?:static\s+)?(?:final\s+|readonly\s+|const\s+)(?:[A-Za-z_][\w<>.\[\]]*\s+)?[A-Za-z_]\w*(?:\s*:\s*[^=]+)?\s*=\s*(?:["'`][^"'`]*["'`]|-?\d+(?:\.\d+)?)\s*;?\s*$/.test(
      trimmed,
    )
  ) {
    return true;
  }
  // TS/JS/Rust/Go bare `const NAME = "literal"` (no visibility keyword)
  if (
    /^(?:const|let|var|static)\s+[A-Za-z_]\w*(?:\s*:\s*[^=]+)?\s*=\s*(?:["'`][^"'`]*["'`]|-?\d+(?:\.\d+)?)\s*;?\s*$/.test(
      trimmed,
    )
  ) {
    return true;
  }
  // Java-style `private static final String X;` (no initializer)
  if (
    /^(?:(?:public|private|protected)\s+)?(?:static\s+)?(?:final\s+)[A-Za-z_][\w<>.\[\]]*\s+[A-Za-z_]\w*\s*;\s*$/.test(
      trimmed,
    )
  ) {
    return true;
  }

  return false;
}

/**
 * Python: import/from, hash-comment, decorators, module-level ALL_CAPS
 * literal constants.
 */
function isNonExecutablePython(trimmed: string): boolean {
  if (/^(import|from)\s/.test(trimmed)) return true;
  if (trimmed.startsWith('#')) return true;
  // Docstring open/close (best effort — full string tracking would need
  // AST). A line that's purely `"""` or `'''` (open/close) is non-executable.
  if (trimmed === '"""' || trimmed === "'''") return true;
  // Decorator on its own line.
  if (/^@[A-Za-z_][\w.]*(?:\s*\([^)]*\))?\s*$/.test(trimmed)) return true;
  // Module-level UPPER_SNAKE = "literal" | 42
  if (
    /^[A-Z_][A-Z0-9_]*\s*(?::\s*[^=]+)?\s*=\s*(?:["'][^"']*["']|-?\d+(?:\.\d+)?)\s*$/.test(
      trimmed,
    )
  ) {
    return true;
  }
  return false;
}
