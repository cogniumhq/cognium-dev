/**
 * Guardrails on reviewer.yml (conformis #894 pattern): draft-only gate, pull_request_target, base checkout.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const workflow = readFileSync(join(root, '.github/workflows/reviewer.yml'), 'utf8');

const reviewJobIf = () => {
  const block = workflow.slice(workflow.indexOf('\n  review:'), workflow.indexOf('\n    runs-on:'));
  const m = block.match(/\n\s+if:\s*(.+)/);
  assert.ok(m, 'review job has if');
  return m[1].trim();
};

test('non-draft PRs only; pull_request_target; script from base ref', () => {
  assert.equal(reviewJobIf(), 'github.event.pull_request.draft == false');
  assert.match(workflow, /pull_request_target:/);
  assert.match(workflow, /ref:\s*\$\{\{\s*github\.event\.pull_request\.base\.ref\s*\}\}/);
  assert.doesNotMatch(workflow, /\bagent-pr\b/);
});