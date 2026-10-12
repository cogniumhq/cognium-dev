# @cognium/html-index

A static index of built HTML. It reads a folder of pages without a browser and reports facts about the markup: which elements there are, what role and accessible name each has, which IDREFs resolve, what the stylesheets say. It reports observations only and never a verdict.

```bash
npm install @cognium/html-index
```

ESM only, Node.js 20.19 or later.

## What it observes

`runHtmlIndex(root, views, params)` returns one observation per `.html` / `.htm` page under `root`:

| Field | What it holds |
|---|---|
| `path`, `lang`, `title`, `malformed`, `viewport` | Page-level facts. `malformed` is true when the tags do not balance. |
| `elements` | Every element in document order: tag, attributes, line, ancestors, ARIA role (explicit, implicit, effective, context), owned roles, accessible name and its source, label association, hidden-ness, focusability, inline event handlers, `:nth-of-type` position, and the visible text beside the name as normalised keys (`labelInName`). |
| `idrefs` | One row per IDREF token of the attributes you name in `params.idrefAttributes`: whether it resolves, whether the target id is duplicated, and table structure for `headers`. |
| `media` | `audio` and `video` elements with their tracks, `autoplay`, `muted`, `controls`. |
| `langAttributes` | Elements with `lang`, and whether each governs rendered text. |
| `cssRules` | Rules of every linked sheet under the root and every `<style>` block, with media queries, net rotation, the frame or shadow host a rule belongs to, and how many elements the selector could match. |
| `frames` | Each `iframe` / `frame`, whether its document was read, and why not. |
| `texts` | The text a reader meets, one row per element that holds a text run of its own. |

A frame's document (`srcdoc`, or a `src` inside the root) and a declarative shadow root are part of the page: their rows are appended after the page's own, with ids offset.

`runFileIndex(root, params)` returns one observation for the tree: every file with its sha256 and size, the text of files matching `params.pathPattern`, and the lines that contain any of `params.patterns`.

Both return an envelope with `schemaVersion` (`"0.1"`), an `inputDigest` per observation and an `environmentDigest`. The same input gives the same bytes.

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

Every result carries `schemaVersion`, currently `"0.1"` (exported as `SCHEMA_VERSION`). It names the shape of the observations, separately from the package version. Pin it and refuse any other value: while it is `0.x`, a change of shape changes the number.

## Limits

- The parser is forgiving and is not a conforming HTML parser. It does not create implied elements or decode character references in attributes.
- Nothing is rendered. No script runs and no stylesheet is applied, so anything computed (generated content, CSS-hidden text, script-built DOM) is outside what it can see. `couldMatch` and `labelInName.styleRisks` over-report by design.
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
