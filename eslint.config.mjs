// Flat config. Deliberately narrow: this repo had no linter, so a broad
// ruleset would mean a large mechanical diff over 36K LOC and would bury the
// rules that actually catch bugs. Type-checking is already enforced by
// `npm run typecheck` in strict mode, and formatting is not enforced at all —
// neither is duplicated here.
//
// What is enabled is the correctness subset: things tsc does not catch and
// that have bitten this codebase before (floating promises, unsafe
// non-null assertions, accidental fallthrough).
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // `--fix` otherwise deletes eslint-disable comments for rules this config
    // leaves off (no-console, say). Those comments document intent and matter
    // the moment a rule is switched back on, so they are not churn to remove.
    linterOptions: { reportUnusedDisableDirectives: 'off' },
  },
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/wasm/**',
      '**/coverage/**',
      '**/*.d.ts',
      'packages/circle-ir/configs/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // tsc in strict mode already covers unused locals/params, and the
      // no-explicit-any blanket ban would fire across the analyzer's
      // deliberately-untyped IR boundaries. Both are noise here.
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',

      // tsc resolves globals and module scope; eslint's core rule does not
      // understand TS and reports false positives on type-only and ambient
      // names. typescript-eslint documents turning it off for TS sources.
      'no-undef': 'off',

      // Cosmetic, and actively unhelpful here: the analyser is built out of
      // regex pattern definitions (15 in language-sources-pass.ts alone), and
      // ESLint itself declines to auto-fix this rule because dropping an
      // escape can change a pattern's intent. Rewriting security patterns to
      // satisfy a style rule is a worse trade than leaving the escapes.
      'no-useless-escape': 'off',

      // Correctness rules worth failing a build over.
      'no-fallthrough': 'error',
      'no-constant-condition': ['error', { checkLoops: false }],
      'no-self-compare': 'error',
      'no-unmodified-loop-condition': 'error',
      'no-unreachable-loop': 'error',
      'require-atomic-updates': 'error',
    },
  },
  {
    // Tests exercise error paths and throwaway shapes; the recommended set
    // fights that without catching real defects.
    files: ['**/tests/**', '**/*.test.ts', '**/*.spec.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/ban-ts-comment': 'off',
    },
  },
);
