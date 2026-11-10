// Regex lint (S3, 8 Nov security Request). Separate from eslint.config.mjs so
// `npm run lint` stays the narrow correctness set; run by
// `scripts/regex-lint.mjs`, which gates on a per-file baseline. Two rules from
// eslint-plugin-regexp: a quantifier that can backtrack super-linearly, and a
// pattern that is super-linear when the engine retries it at every position.
import tseslint from 'typescript-eslint';
import regexp from 'eslint-plugin-regexp';

export default [
  { linterOptions: { reportUnusedDisableDirectives: 'off' } },
  { ignores: ['**/dist/**', '**/node_modules/**', '**/wasm/**', '**/coverage/**', '**/*.d.ts'] },
  {
    files: ['packages/*/src/**/*.ts'],
    languageOptions: { parser: tseslint.parser },
    plugins: { regexp },
    rules: {
      'regexp/no-super-linear-backtracking': 'error',
      'regexp/no-super-linear-move': 'error',
    },
  },
];
