/**
 * Pass #35: missing-public-doc (category: maintainability)
 *
 * Detects public/exported methods and types that have no doc comment.
 * A "doc comment" is a Javadoc-style `/** ... *\/` block, a TypeScript/JS
 * JSDoc `/** ... *\/` block, a Rust `///` line comment, or a Python docstring
 * (`"""..."""` as the first statement of the function body).
 *
 * What counts as "public":
 *   - Java / Kotlin: `modifiers` contains `"public"`.
 *   - JavaScript / TypeScript: `modifiers` does NOT contain `"private"` or
 *     `"protected"`. (JS has no access keywords; everything is implicitly public.)
 *   - Python: method name does not start with `_`.
 *   - Rust / Bash / other: skipped (doc conventions differ too much).
 *
 * Types (classes, interfaces) are always checked — they are extracted only when
 * they are top-level declarations and therefore always "public" in the IR sense.
 *
 * Test files are excluded: if the file path contains test/spec patterns, the
 * pass emits no findings (doc comments in test helpers are low value).
 */

import type { MethodInfo, TypeInfo } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Files matching these path patterns are treated as test/spec files. */
const TEST_PATH_RE = /[/._](test|tests|spec|specs|__tests?__|__mocks?__)[/._]/i;

/**
 * Files in common utility/helper directories are implementation details, not
 * public library API. Requiring JSDoc on every class in these directories
 * produces noise when the project is a CLI tool or application.
 */
const UTIL_DIR_RE = /[/](utils?|helpers?|internal|private|common|shared)[/]/i;

/** Checks whether a single character position is a doc-comment start. */
function hasDocCommentBefore(lines: string[], startLine: number): boolean {
  // Look back up to 10 lines (handles multi-line annotations + blank lines).
  const limit = Math.max(0, startLine - 11);
  for (let i = startLine - 2; i >= limit; i--) {
    const trimmed = lines[i]?.trim() ?? '';
    if (trimmed === '') continue;                       // blank — keep looking
    if (trimmed.startsWith('/**') ||                    // Javadoc / JSDoc open
        trimmed.startsWith('*/') ||                     // mid-block or close
        trimmed.startsWith('*') ||                      // doc block body line
        trimmed.startsWith('///') ||                    // Rust / C# doc comment
        trimmed.startsWith('//!')) {                    // Rust inner doc
      return true;
    }
    // If we hit a non-blank, non-doc line that isn't an annotation or decorator,
    // stop searching — we've gone past any preceding doc block.
    if (!trimmed.startsWith('@') && !trimmed.startsWith('#[')) break;
  }
  return false;
}

/** Check whether the first statement in the method body is a Python docstring. */
function hasPythonDocstring(lines: string[], method: MethodInfo): boolean {
  const bodyStart = method.start_line; // start_line is the `def` line (1-indexed)
  const limit = Math.min(bodyStart + 4, lines.length);
  for (let i = bodyStart; i < limit; i++) {
    const trimmed = lines[i]?.trim() ?? '';
    if (trimmed === '') continue;
    return trimmed.startsWith('"""') || trimmed.startsWith("'''");
  }
  return false;
}

function isPublicMethod(method: MethodInfo, language: string): boolean {
  switch (language) {
    case 'java':
      return method.modifiers.includes('public');
    case 'javascript':
    case 'typescript':
      return !method.modifiers.includes('private') &&
             !method.modifiers.includes('protected');
    case 'python':
      return !method.name.startsWith('_');
    default:
      return false; // Rust, Bash, etc. — skip
  }
}

export interface MissingPublicDocPassResult {
  missingDocMethods: Array<{ type: TypeInfo; method: MethodInfo }>;
  missingDocTypes: TypeInfo[];
}

export class MissingPublicDocPass implements AnalysisPass<MissingPublicDocPassResult> {
  readonly name = 'missing-public-doc';
  readonly category = 'maintainability' as const;

  run(ctx: PassContext): MissingPublicDocPassResult {
    const { graph, code, language } = ctx;

    // Skip test/spec files — doc comments in test helpers are low value.
    if (TEST_PATH_RE.test(graph.ir.meta.file)) {
      return { missingDocMethods: [], missingDocTypes: [] };
    }

    // Skip files inside utility/helper directories — these are internal
    // implementation details, not public library API surfaces.
    if (UTIL_DIR_RE.test(graph.ir.meta.file)) {
      return { missingDocMethods: [], missingDocTypes: [] };
    }

    // Only supported languages.
    if (!['java', 'javascript', 'typescript', 'python'].includes(language)) {
      return { missingDocMethods: [], missingDocTypes: [] };
    }

    const lines = code.split('\n');
    const file = graph.ir.meta.file;

    const missingDocMethods: Array<{ type: TypeInfo; method: MethodInfo }> = [];
    const missingDocTypes: TypeInfo[] = [];

    for (const type of graph.ir.types) {
      // Skip the synthetic '<module>' type used to group top-level functions.
      // It is not a real class/interface and requiring a doc comment on it
      // produces misleading findings for every TypeScript/JavaScript file.
      if (type.name === '<module>') continue;

      // Check type-level doc comment.
      if (!hasDocCommentBefore(lines, type.start_line)) {
        missingDocTypes.push(type);
        ctx.addFinding({
          id: `missing-public-doc-${file}-${type.start_line}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          severity: 'low',
          level: 'note',
          message: `Missing doc comment on ${type.kind} \`${type.name}\``,
          file,
          line: type.start_line,
          fix: `Add a /** ... */ doc comment above \`${type.kind} ${type.name}\``,
        });
      }

      // Check method-level doc comments for public methods.
      for (const method of type.methods) {
        if (!isPublicMethod(method, language)) continue;

        const documented = language === 'python'
          ? hasPythonDocstring(lines, method)
          : hasDocCommentBefore(lines, method.start_line);

        if (!documented) {
          missingDocMethods.push({ type, method });
          ctx.addFinding({
            id: `missing-public-doc-${file}-${method.start_line}`,
            pass: this.name,
            category: this.category,
            rule_id: this.name,
            severity: 'low',
            level: 'note',
            message: `Missing doc comment on public method \`${type.name}.${method.name}\``,
            file,
            line: method.start_line,
            fix: `Add a /** ... */ doc comment above \`${method.name}\``,
          });
        }
      }
    }

    return { missingDocMethods, missingDocTypes };
  }
}
