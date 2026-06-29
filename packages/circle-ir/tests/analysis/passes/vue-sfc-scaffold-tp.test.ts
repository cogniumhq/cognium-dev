/**
 * Sprint 63 — cognium-dev #184 Vue SFC scaffold (sprint 1 of 2).
 *
 * Adds routing infrastructure for `.vue` Single-File Components so the
 * existing JS pipeline analyzes `<script>` and `<script setup>` blocks.
 * Reuses tree-sitter-html under the hood: probe with
 * `analyze(vueSrc, 'Foo.vue', 'html')` against HEAD confirms the html
 * grammar parses `<template>` / `<script>` / `<style>` blocks identically
 * to a plain HTML document, so script extraction "just works" once the
 * `'vue'` language tag is added to the SupportedLanguage union.
 *
 * Sprint 63 scope = JS-side detection only. Vue template attribute
 * sinks (`v-html`, `v-text`, `:innerHTML`) are explicitly out of scope
 * and land in Sprint 64 as a new vue-template-xss pass. FN-1 below
 * documents and locks that gap until then.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countSinks = (r: { taint?: { sinks?: unknown[] } }) =>
  r.taint?.sinks?.length ?? 0;

describe('cognium-dev #184 — Vue SFC scaffold (JS pipeline routing)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // TP cases — script blocks inside .vue files reach the JS taint pipeline
  // -------------------------------------------------------------------------

  it('#184 TP-1 — Vue SFC <script> block: tainted eval registers as a sink', async () => {
    const code = `<template>
  <div>hello</div>
</template>

<script>
const userInput = req.body.payload;
eval(userInput);
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    // taint.sinks captures the eval() — equivalent to the plain-HTML
    // script-extraction path verified in html-extractor tests.
    expect(countSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('#184 TP-2 — Vue SFC <script setup>: tainted eval registers as a sink', async () => {
    const code = `<template>
  <div>hello</div>
</template>

<script setup>
const userInput = req.body.payload;
eval(userInput);
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(countSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('#184 TP-3 — Vue SFC <script lang="ts">: routed to TS pipeline', async () => {
    const code = `<template>
  <div>hello</div>
</template>

<script lang="ts">
const userInput: string = req.body.payload;
eval(userInput);
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(countSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('#184 TP-4 — Vue SFC with template only: no crash, no findings', async () => {
    const code = `<template>
  <div class="hello">{{ msg }}</div>
</template>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(countSinks(r)).toBe(0);
    expect(r.findings ?? []).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // FN-1 — Sprint 64 contract lock (template-side v-html NOT detected today)
  // -------------------------------------------------------------------------

  it('#184 FN-1 — Vue SFC <template v-html="taint">: documented FN (Sprint 64)', async () => {
    // Tainted value bound to v-html. Sprint 63 does NOT walk the
    // <template> subtree, so this currently produces zero XSS findings.
    // When Sprint 64 lands the vue-template-xss pass, this expectation
    // flips to .toBeGreaterThanOrEqual(1) and becomes TP-5.
    const code = `<template>
  <div v-html="userInput"></div>
</template>

<script setup>
const userInput = req.body.payload;
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    const xssFindings = (r.findings ?? []).filter(
      (f) => f.rule_id === 'xss' || f.cwe === 'CWE-79',
    );
    expect(xssFindings.length).toBe(0);
  });
});
