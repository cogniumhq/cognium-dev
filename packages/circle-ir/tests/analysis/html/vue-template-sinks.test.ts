/**
 * Vue Single-File Component template sinks.
 *
 * A raw-HTML template binding (`v-html`, `:innerHTML`, …) is a DOM sink for
 * its expression. The script block is analysed with each binding written as
 * a DOM sink, so taint is decided by the same engine as plain JS, and the
 * flow is reported from the script's source line to the binding's line in
 * the `.vue` file.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import { initParser, parse } from '../../../src/core/parser.js';
import {
  buildVueTemplateProbes,
  collectVueHtmlBindings,
} from '../../../src/analysis/html/vue-template-xss-pass.js';

type Flow = { source_line: number; sink_line: number; sink_type: string };
const xssFlows = (r: { taint: { flows?: Flow[] } }): Array<[number, number]> =>
  (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => [f.source_line, f.sink_line]);

describe('Vue SFC template HTML sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
    await initParser();
  });

  describe('flows from <script setup>', () => {
    it('URLSearchParams value bound with v-html: script line → template line', async () => {
      const code = [
        '<template>',
        '  <div v-html="message"></div>',
        '</template>',
        '',
        '<script setup>',
        'const params = new URLSearchParams(window.location.search);',
        "const message = params.get('msg');",
        '</script>',
      ].join('\n');
      const r = await analyze(code, 'Banner.vue', 'vue');
      expect(xssFlows(r)).toEqual([[7, 2]]);
      expect(r.taint.sinks.some((s) => s.line === 2 && s.type === 'xss')).toBe(true);
    });

    it('Vue Router `useRoute()` query value', async () => {
      const code = [
        '<template>',
        '  <div v-html="msg"></div>',
        '</template>',
        '<script setup>',
        "import { useRoute } from 'vue-router';",
        'const route = useRoute();',
        'const msg = route.query.msg;',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'A.vue', 'vue'))).toEqual([[6, 2]]);
    });

    it('`useRoute().query` read inline', async () => {
      const code = [
        '<template>',
        '  <p :innerHTML="title"></p>',
        '</template>',
        '<script setup>',
        'const title = useRoute().query.title;',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'T.vue', 'vue')).map(([, sink]) => sink)).toEqual([2]);
    });

    it('`computed()` over route params in a `lang="ts"` block', async () => {
      const code = [
        '<template>',
        '  <div v-html="html"></div>',
        '</template>',
        '<script setup lang="ts">',
        "import { computed } from 'vue';",
        "import { useRoute } from 'vue-router';",
        'const route = useRoute();',
        'const html = computed(() => route.params.slug as string);',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'B.vue', 'vue')).map(([, sink]) => sink)).toEqual([2]);
    });

    it('`$route.query` read in the template itself', async () => {
      const code = [
        '<template>',
        '  <div v-html="$route.query.msg"></div>',
        '</template>',
        '<script setup>',
        'const unused = 1;',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'R.vue', 'vue'))).toEqual([[2, 2]]);
    });
  });

  describe('flows from an Options API component', () => {
    it('computed property returning `this.$route.query`', async () => {
      const code = [
        '<template>',
        '  <div v-html="note"></div>',
        '</template>',
        '',
        '<script>',
        'export default {',
        '  computed: {',
        '    note() {',
        '      return this.$route.query.note;',
        '    },',
        '  },',
        '};',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'C.vue', 'vue'))).toEqual([[9, 2]]);
    });

    it('data() key from `this.$route.params`', async () => {
      const code = [
        '<template>',
        '  <div v-html="body"></div>',
        '</template>',
        '<script>',
        'export default {',
        '  data() {',
        '    return { body: this.$route.params.body };',
        '  },',
        '};',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'G.vue', 'vue'))).toEqual([[7, 2]]);
    });

    it('setup() return: only the tainted key fires', async () => {
      const code = [
        '<template>',
        '  <section>',
        '    <div v-html="msg"></div>',
        '    <div v-html="other"></div>',
        '  </section>',
        '</template>',
        '<script>',
        "import { useRoute } from 'vue-router';",
        'export default defineComponent({',
        '  setup() {',
        '    const route = useRoute();',
        '    const msg = route.query.m;',
        "    const other = 'static';",
        '    return { msg, other };',
        '  },',
        '});',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'H.vue', 'vue')).map(([, sink]) => sink)).toEqual([3]);
    });
  });

  describe('no flow', () => {
    it('value passed through DOMPurify.sanitize', async () => {
      const code = [
        '<template>',
        '  <div v-html="clean"></div>',
        '</template>',
        '<script setup>',
        "import DOMPurify from 'dompurify';",
        'const params = new URLSearchParams(window.location.search);',
        "const clean = DOMPurify.sanitize(params.get('msg'));",
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'D.vue', 'vue'))).toEqual([]);
    });

    it('constant bound with v-html; tainted value shown only as text', async () => {
      const code = [
        '<template>',
        '  <div v-html="greeting"></div>',
        '  <p>{{ msg }}</p>',
        '  <p v-text="msg"></p>',
        '</template>',
        '<script setup>',
        'const params = new URLSearchParams(window.location.search);',
        "const msg = params.get('msg');",
        "const greeting = '<b>Hello</b>';",
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'E.vue', 'vue'))).toEqual([]);
    });

    it('component props', async () => {
      const code = [
        '<template>',
        '  <div v-html="props.html"></div>',
        '</template>',
        '<script setup>',
        'const props = defineProps({ html: String });',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'P.vue', 'vue'))).toEqual([]);
    });

    it('Options API: a prop, the route name, and a call wrapping the member', async () => {
      const code = [
        '<template>',
        '  <div v-html="note"></div>',
        '  <div v-html="name"></div>',
        '  <div v-html="sanitize(query)"></div>',
        '</template>',
        '<script>',
        'export default {',
        "  props: ['note'],",
        '  computed: {',
        '    name() {',
        '      return this.$route.name;',
        '    },',
        '    query() {',
        '      return this.$route.query.q;',
        '    },',
        '  },',
        '};',
        '</script>',
      ].join('\n');
      expect(xssFlows(await analyze(code, 'J.vue', 'vue'))).toEqual([]);
    });
  });

  it('a <script setup> binding read only by the template is not an unused variable', async () => {
    const code = [
      '<template>',
      '  <p>{{ shown }}</p>',
      '</template>',
      '<script setup>',
      'const shown = 1;',
      'const neverRead = 2;',
      '</script>',
    ].join('\n');
    const r = await analyze(code, 'U.vue', 'vue');
    const unused = (r.findings ?? []).filter((f) => f.rule_id === 'unused-variable').map((f) => f.evidence?.variable);
    expect(unused).toEqual(['neverRead']);
  });

  describe('probe construction', () => {
    it('keeps script lines and appends one sink line per binding', async () => {
      const html = await parse(
        '<template>\n  <div v-html="a"></div>\n  <div :innerHTML="b.c"></div>\n  <div v-html="\'<b>x</b>\'"></div>\n</template>\n',
        'html',
      );
      const bindings = collectVueHtmlBindings(html.rootNode);
      html.delete();
      expect(bindings.map((b) => [b.attribute, b.expression, b.line])).toEqual([
        ['v-html', 'a', 2],
        [':innerHTML', 'b.c', 3],
      ]);

      const script = '\nconst a = 1\nconst b = { c: 2 }\n';
      const tree = await parse(script, 'javascript');
      const probes = buildVueTemplateProbes(script, tree.rootNode, bindings);
      tree.delete();
      expect(probes).toHaveLength(1);
      const lines = probes[0].code.split('\n');
      expect(lines.slice(0, 4)).toEqual(script.split('\n'));
      expect(probes[0].scriptLineCount).toBe(4);
      expect([...probes[0].sinkLines.entries()].map(([l, b]) => [l, b.line])).toEqual([[5, 2], [6, 3]]);
    });

    it('wraps a shorthand setup() key in place without adding a line', async () => {
      const html = await parse('<template><div v-html="msg"></div></template>', 'html');
      const bindings = collectVueHtmlBindings(html.rootNode);
      html.delete();
      const script = 'export default {\n  setup() {\n    return { msg };\n  },\n};';
      const tree = await parse(script, 'javascript');
      const [probe] = buildVueTemplateProbes(script, tree.rootNode, bindings);
      tree.delete();
      const lines = probe.code.split('\n');
      expect(lines[2]).toBe('    return { msg: __vueTemplateHtml__.innerHTML = (msg) };');
      expect(probe.sinkLines.get(3)?.line).toBe(1);
    });
  });
});
