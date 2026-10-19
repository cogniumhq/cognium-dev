/**
 * A sample of the framework handler table `runHtmlIndex` takes (`HtmlIndexParams.markupHandlers`),
 * written for these tests. It is not a complete catalog: a caller passes its own, and none ships with
 * the package. Order matters: an attribute is recognised by the first row it matches.
 */
import type { MarkupHandlerRule } from '../../src/html-index.js';

export const markupHandlers: MarkupHandlerRule[] = [
  { framework: 'vue', attr: '@([a-z][\\w-]*)[\\w.:-]*', event: { group: 1 } },
  { framework: 'vue', attr: 'v-on:([a-z][\\w-]*)[\\w.-]*', event: { group: 1 } },
  { framework: 'alpine', attr: 'x-on:([a-z][\\w-]*)[\\w.-]*', event: { group: 1 } },
  { framework: 'angular', attr: '\\(([a-z][\\w-]*)[\\w.-]*\\)', event: { group: 1 } },
  { framework: 'htmx', attr: 'hx-trigger', event: { value: '(?:^|,)\\s*([a-z][\\w:-]*)' } },
  { framework: 'htmx', attr: 'hx-(?:get|post|put|patch|delete)' },
  { framework: 'stimulus', attr: 'data-action', event: { value: '(?:^|\\s)(?:([a-z][\\w:-]*)->)?[\\w-]+#' } },
];
