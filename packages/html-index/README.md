# @cognium/html-index

A static index of built HTML. It reads a folder of pages without a browser and reports facts about the markup: which elements there are, what role, accessible name and visible label each has, which IDREFs resolve, what the stylesheets say, and how the site's navigations line up across pages. It reports observations only and never a verdict.

```bash
npm install @cognium/html-index
```

ESM only, Node.js 20.19 or later.

## What it observes

`runHtmlIndex(root, views, params)` returns one observation per `.html` / `.htm` page under `root`:

| Field | What it holds |
|---|---|
| `path`, `lang`, `title`, `malformed`, `viewport` | Page-level facts. `malformed` is true when the tags do not balance. |
| `parseErrors` | What set `malformed`, one row per thing the forgiving parser noticed: `stray-end-tag`, `misnested-end-tag`, `unclosed-raw-text`, `unclosed-at-end`, each with its line, the tag and the elements it left open. Empty exactly when `malformed` is false. Conforming markup can produce a row (an optional end tag the parser does not imply). |
| `elements` | Every element in document order: tag, attributes, line, ancestors, ARIA role (explicit, implicit, effective, context), owned roles, accessible name and its source, label association, hidden-ness, focusability, inline event handlers, `:nth-of-type` position, the visible text beside the name as normalised keys (`labelInName`), and the fields below. |
| `elements[].visibleLabelText` | The text a sighted user reads as the label, beside `name`. A form field: its `<label>` text, else its rendered `aria-labelledby` targets'. A submit, reset or button input: its `value`. Anything else: its own visible text, else its labels'. `aria-hidden` text counts; text under `hidden`, `alt`, `title`, `aria-label` and `placeholder` never do. `""` when nothing is visible. |
| `elements[].lang`, `langFrom` | The language in force: the nearest `lang` on the element or an ancestor, trimmed, and the id of the element that states it. `""` is a language declared unknown, inherited as such; null is no `lang` anywhere above. |
| `elements[].css` | `{ animation, textDecoration }`: every author declaration of the `animation*` and `text-decoration*` families that matches the element at rest, lowest precedence first (normal before `!important`, stylesheets before the inline style, then specificity, then source order). Each has `property`, `value`, `important`, `media` (the rule's `@media`), `sheetMedia` (the `<link>` or `<style>` `media`), `inline` and `source` (`file`, `line`, `selector`). Conditions are listed, not evaluated. |
| `idrefs` | One row per IDREF token of the attributes you name in `params.idrefAttributes`: whether it resolves, whether the target id is duplicated, and table structure for `headers`. |
| `idrefEdges`, `duplicateIds` | The same tokens as edges with both ends (`from`, `to` as element ids, with their lines), `dangling`, `duplicate`, `targets` (how many elements hold the id) and `selfReference`; and every id two or more elements hold, with their element ids and lines. |
| `media` | `audio` and `video` elements with their tracks, `autoplay`, `muted`, `controls`. |
| `langAttributes` | Elements with `lang`, and whether each governs rendered text. |
| `cssRules` | Rules of every linked sheet under the root and every `<style>` block, with media queries, net rotation, the frame or shadow host a rule belongs to, and how many elements the selector could match. |
| `stylesheets` | The same rules grouped by sheet, in the same order, with the sheet's `kind` (`linked` or `inline`), the line of its `<link>` or `<style>`, its `media` attribute, its `href`, and whether it `resolved`: a linked sheet the root does not hold is listed with no rules. |
| `frames` | Each `iframe` / `frame`, whether its document was read, and why not. |
| `texts` | The text a reader meets, one row per element that holds a text run of its own. |

A frame's document (`srcdoc`, or a `src` inside the root) and a declarative shadow root are part of the page: their rows are appended after the page's own, with ids offset.

`runFileIndex(root, params)` returns one observation for the tree: every file with its sha256 and size, the text of files matching `params.pathPattern`, and the lines that contain any of `params.patterns`.

`runRouteIndex(root, views, params, pages?)` returns one observation for the site (anchor `site`), read off the pages' html-index observations, so a consumer can compare repeated components across pages:

| Field | What it holds |
|---|---|
| `pages` | Each page with its navigation blocks and compared component links. A `malformed` page is listed and not compared. |
| `navigations` | One row per (block, page). A block is an element with role `navigation` that is not hidden, keyed by its normalised accessible name (`navigation "main"`) or its position among the page's unnamed ones (`navigation (unnamed #1)`). `destinations` in document order; `reference` is the first page in path order holding the block; `pageOrder` and `referenceOrder` are the destinations both hold, in each page's order; `orderDiffers`. |
| `identifications` | One row per (component, destination, page) for links whose nearest landmark is a navigation, banner or contentinfo: the names the page gives the destination (normalised, and as shown), and the names only this page or only the reference page uses. |
| `pageCount`, `pagesCompared`, `repeatedNavigations`, `repeatedComponentLinks`, `linksOffSite` | Counts. |

A destination is the link's `href` resolved against the page or its `<base href>`, fragment dropped, query kept, with `/about`, `/about/` and `/about/index.html` read as one. Only the site's own: a relative URL, or an absolute one whose origin is in `params.origins`. If you already ran `runHtmlIndex`, `routeIndexRun(anchors, params)` builds the observation from its anchors (pass the pages you want compared); `destinationOf` and `normaliseName` are exported as well.

All three return an envelope with `schemaVersion` (`"0.2"`), an `inputDigest` per observation and an `environmentDigest`. The same input gives the same bytes.

## Tables are inputs

The role and name algorithms follow the W3C specifications (ARIA 1.2, ARIA in HTML, Accessible Name 1.2). The tables they read are passed in by the caller as `views`; none ships with the package.

`aria` holds `role-names`, `global-attributes`, `name-from-contents` and `required-owned`. `html` holds `row-match`, `tag-row`, `implicit-role-by-row` and `implicit-role-by-tag-default`. The types are `AriaViews` and `HtmlAriaViews`; [`tests/fixtures/views.ts`](https://github.com/cogniumhq/cognium-dev/blob/main/packages/html-index/tests/fixtures/views.ts) in the repository is a small sample.

## Usage

```ts
import { readFileSync } from 'node:fs';
import { runHtmlIndex, SCHEMA_VERSION, type AriaViews, type HtmlAriaViews, type PageObservation } from '@cognium/html-index';

// Your own tables, built from the W3C specifications.
const aria: AriaViews = JSON.parse(readFileSync('aria-views.json', 'utf8'));
const html: HtmlAriaViews = JSON.parse(readFileSync('html-aria-views.json', 'utf8'));

const result = runHtmlIndex('/path/to/site', { html, aria }, { idrefAttributes: ['aria-labelledby', 'for'] });
if (result.schemaVersion !== SCHEMA_VERSION) throw new Error(`unexpected schema ${result.schemaVersion}`);

for (const { anchor, observation } of result.anchors) {
  const page = observation as PageObservation; // anchor is the page path
  for (const el of page.elements) console.log(anchor, el.line, el.tag, el.effectiveRole, el.name);
}
```

## Schema version

Every result carries `schemaVersion`, currently `"0.2"` (exported as `SCHEMA_VERSION`). It names the shape of the observations, separately from the package version. Pin it and refuse any other value: while it is `0.x`, a change of shape changes the number.

`"0.2"` is additive over `"0.1"`: it adds `parseErrors`, `idrefEdges`, `duplicateIds` and `stylesheets` to each page, `visibleLabelText`, `lang`, `langFrom` and `css` to each element, and the `route-index` capability. Every `"0.1"` field has the same value on the same input, and every input digest is unchanged.

## Limits

- The parser is forgiving and is not a conforming HTML parser. It does not create implied elements or decode character references in attributes.
- Nothing is rendered. No script runs and no stylesheet is applied, so anything computed (generated content, CSS-hidden text, script-built DOM) is outside what it can see. `couldMatch` and `labelInName.styleRisks` over-report by design.
- `elements[].css` matches selectors where a static tree decides them. `:has()`, `:nth-child(… of S)`, `:lang()`, `:dir()`, namespaced selectors and pseudo-classes it does not know are not evaluated, and a rule that needs one is not listed for the element. `@import` is not followed, and `@supports`, `@layer` and `@container` are not reported as conditions.
- `visibleLabelText` reads the markup only: text a stylesheet hides and generated content are not accounted for (`labelInName.styleRisks` says when that could matter).
- It uses `node:fs`, `node:path` and `node:crypto`, so it runs in Node.js only.

## Development

```bash
npm run build -w packages/html-index
npm run test -w packages/html-index
npm run test:coverage -w packages/html-index
```

### Accessible-name baseline

`bench/wpt-accname.mjs` reads the [web-platform-tests](https://github.com/web-platform-tests/wpt) `accname/` expectations as text and compares each expected name with the one this package computes. It is a baseline to measure later versions against, not a test gate.

```bash
node bench/wpt-accname.mjs --wpt <wpt checkout> --aria <aria views.json> --html <html-aria views.json>
```

Version 0.1.0, WPT commit `718b59fdd6e89acdc5b67b19fb3182cf14dd2f46`, with complete ARIA 1.2 and ARIA in HTML tables as input: 645 cases, 421 pass, 209 fail, 15 not applicable. A case is not applicable when it expects something other than a name or its element is not in the markup.

## License

MIT
