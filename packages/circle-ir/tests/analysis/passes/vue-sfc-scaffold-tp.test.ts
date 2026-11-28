/**
 * cognium-dev #184 — Vue SFC detection (sprints 63 + 64).
 *
 * Sprint 63 added `.vue` routing through tree-sitter-html so the
 * existing JS pipeline picks up `<script>` / `<script setup>` /
 * `<script lang="ts">` blocks (TP-1..TP-4 below).
 *
 * Sprint 64 added template-attribute sinks: `v-html`, `v-bind:innerHTML`,
 * `:innerHTML`, `v-bind:outerHTML` and `:outerHTML` bindings whose
 * expression carries taint from the file's script blocks (TP-5..TP-7 +
 * TN-1..TN-2 below). They are reported as `xss` taint flows ending at the
 * binding's template line.
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
  // Sprint 64 — vue-template-xss pass (template attribute bindings)
  // -------------------------------------------------------------------------

  // A raw-HTML template binding is reported as an `xss` taint flow whose
  // sink is the binding's line in the `.vue` file (line 2 in every case).
  const vueXssFindings = (r: { taint: { flows?: Array<{ sink_type: string; sink_line: number }> } }) =>
    (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss' && f.sink_line === 2);

  it('#184 TP-5 — Vue SFC <template v-html="taint">: reports an xss flow to the binding', async () => {
    // Sprint 63 locked this at zero; Sprint 64 flips it to a real TP.
    const code = `<template>
  <div v-html="userInput"></div>
</template>

<script setup>
const userInput = req.body.payload;
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(vueXssFindings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('#184 TP-6 — Vue SFC :innerHTML shorthand binding fires', async () => {
    const code = `<template>
  <div :innerHTML="userInput"></div>
</template>

<script setup>
const userInput = req.body.payload;
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(vueXssFindings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('#184 TP-7 — Vue SFC v-bind:innerHTML full form fires', async () => {
    const code = `<template>
  <span v-bind:innerHTML="userInput"></span>
</template>

<script setup>
const userInput = req.body.payload;
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(vueXssFindings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('#184 TN-1 — Vue SFC v-text with taint does NOT fire (textContent is safe)', async () => {
    // v-text writes via textContent which the browser escapes.
    // Even with a tainted RHS this must produce no template xss flow —
    // locks the v-text-is-safe contract.
    const code = `<template>
  <div v-text="userInput"></div>
</template>

<script setup>
const userInput = req.body.payload;
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(vueXssFindings(r).length).toBe(0);
  });

  it('#184 TN-2 — Vue SFC v-html with literal string does NOT fire (no tainted ident)', async () => {
    // No identifier on the RHS matches a tainted def — the binding is
    // a static string literal. Must produce zero findings.
    const code = `<template>
  <div v-html="'<b>literal</b>'"></div>
</template>

<script setup>
const userInput = req.body.payload;
</script>
`;
    const r = await analyze(code, 'Foo.vue', 'vue');
    expect(vueXssFindings(r).length).toBe(0);
  });
});
