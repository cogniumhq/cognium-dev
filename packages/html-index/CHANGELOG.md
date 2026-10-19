# Changelog

All notable changes to `@cognium/html-index` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

Additive: results carry `schemaVersion` `"0.3"`, and every input digest is unchanged. Every 0.2 value keeps its value on every page except accessible names the fixes below move (`name`, and with it `nameSource`, `visibleLabel` and `labelInName`); `texts` and `hasText` read as in 0.2.

### Added
- **`elements[].css.cursor`.** Every author `cursor` declaration that matches the element at rest, in the shape of the other `css` families (`property`, `value`, `important`, `media`, `sheetMedia`, `inline`, `source`), lowest precedence first, plus `inherited` and `from`. When the element declares no cursor, the declarations of the nearest ancestor that does are listed, marked `inherited`, with that ancestor's element id in `from`. No user agent cursor is listed.
- **`elements[].inlineHandlers`.** Every event handler content attribute, in source order, as `{ attr, event, handlerFamily }`: HTML's `GlobalEventHandlers` (with the members Pointer Events, Touch Events, CSS Animations, CSS Transitions and the Selection API add) on any element, and `WindowEventHandlers` on `<body>` and `<frameset>`. An `on*` attribute no specification defines is not listed. `pointerHandlers` and `keyHandlers` are unchanged.
- **`elements[].markupHandlers` and `params.markupHandlers`.** Framework handler attributes that survive into the built markup (`@click`, `v-on:`, `x-on:`, a prerendered `(click)`, `hx-*`, a declarative `data-action` …), as `{ attr, framework, event, handlerFamily }`, recognised by a table the caller passes (`MarkupHandlerRule[]`): an attribute-name pattern, and where the event comes from (a capture group of the name, every match of a pattern over the value, or a fixed type). The engine knows no framework; with no table, no element has any.
- `handlerFamily(event)`: `pointer`, `key`, `focus`, `input` or `other`. `compileMarkupHandlers(rules)` checks a table up front.
- Types `CursorDeclarationObs`, `HandlerFamily`, `InlineHandlerObs`, `MarkupHandlerObs`, `MarkupHandlerRule`.

### Fixed — accessible names (WPT accname, commit `718b59fd`: 421 → 536 of 645)
- **Embedded controls (AccName 1.2 step 2C).** A control inside the label of another widget, or named by `aria-labelledby`, contributes its value: a text box its `value`, a select or ARIA combo box or list box its chosen option(s), a range its `aria-valuetext`, else `aria-valuenow`, else its value (a range input's default is its midpoint); an embedded menu contributes nothing. The value comes before the control's own `aria-label`. A label no longer includes the control it labels, and an `aria-labelledby` target that is a labelled form control gives its label. (+76)
- **Character references and no-break spaces.** Text in a name has its character references decoded, as do the attributes a name reads (`aria-label`, `alt`, `title`, `value`, `placeholder`). Only ASCII white space is collapsed and trimmed, so a no-break space is kept. (+22, and +3 `alt` white-space cases)
- **Spaces between inline children.** Name from content joins a text-level child (`span`, `b`, `a` …) to its neighbours with no space, as the page renders it; a block, `<br>`, white space between tags, or an author `display` other than inline, `float`, or `position: absolute | fixed` is a word boundary. (+14)
- `&nbsp;` in visible text is decoded to U+00A0 (it was a plain space); `visibleLabelText` and the `labelInName` keys are unchanged by it.

### Parity with 0.2.0
On the conformis `a11y-html` and `tech-html-aria` pack fixtures (13 roots, 306 pages, 5,963 elements), every 0.2 field other than a name is unchanged, and 2 names change, both an `aria-label` whose runs of spaces now collapse to one (`nameSource` unchanged). On the pack's govuk-ata-2019 bench sources (142 pages), 8 heading names change, each from a literal `&#39;` to `'`.

### Consumer Impact
A consumer that pins `schemaVersion` `"0.2"` refuses these results, which is loud. One that does not pin it gets no error, but some names are different:
- **`name` text.** A name that held a literal character reference now holds the character (`&#39;` → `'`, `&nbsp;` → U+00A0, `&amp;` → `&`). Runs of ASCII white space inside `aria-label`, `alt`, `title`, `value` and `placeholder` collapse to one space. A no-break space at either end of a name is no longer trimmed. Text-level children join with no space (`one<b>two</b>` was `one two`, is `onetwo`). A label that holds a text field, select or range now includes that control's value (`Flash the screen 3 times`, which was `Flash the screen times`, or included every option). The labelled control's own value or text is never part of its label.
- **What a non-adapting consumer sees.** A comparison against names stored from 0.2 reports a change, with nothing in the markup changed. A string test that matches on `&nbsp;` or `&#39;` stops matching. `labelInName.nameKey` follows `name`. On the pack fixtures this touched 2 of 5,963 names (see Parity).
- **Not affected.** `texts[].text`, `hasText`, `visibleLabelText` and `labelInName.labelKey` read as in 0.2. Every other 0.2 field and every input digest is unchanged. A deep comparison of the whole `css` object sees the new `cursor` key, and that fails loudly.
- **Migration.** Pin `"0.3"`, and take names from 0.3.0 as the new baseline.

### Changed
- `SCHEMA_VERSION` is `"0.3"` and `DRIVER.version` `"0.3.0"`.

## [0.2.0] - 2026-10-15

Additive: every 0.1 field keeps its value on every page, and every input digest is unchanged. Results carry `schemaVersion` `"0.2"`.

### Added
- **`runRouteIndex` / `routeIndexRun`: a new capability, `route-index`.** One observation per site, read off the pages' `html-index` observations: each navigation block (told apart by its normalised accessible name, or its position among the unnamed ones) lined up with the same block on the first page that has it, with the destinations both share in each page's order; and each link of a navigation, banner or contentinfo lined up by destination, with the names each page gives it. A destination is a link resolved against its page or `<base href>`, with `/x`, `/x/` and `/x/index.html` read as one. `destinationOf`, `normaliseName` and `routeIndexOf` are exported too.
- **`elements[].visibleLabelText`.** The text a sighted user reads as the element's label, beside `name`: a form field's `<label>` text, else its rendered `aria-labelledby` targets'; a button input's `value`; anything else's own visible text. `aria-hidden` text counts; text under `hidden`, `alt`, `title`, `aria-label` and `placeholder` do not.
- **`elements[].css`.** Every author declaration of the `animation` and `text-decoration` families that matches the element at rest, lowest precedence first, each with its file, line, selector, `@media` conditions, the sheet's `media` attribute and `important`. Conditions are reported, not evaluated. A new selector matcher decides type, class, id and attribute selectors, all four combinators, structural pseudo-classes, `:not()` / `:is()` / `:where()`, `:link` and the form states the markup states; a selector needing a user action or styling a pseudo-element is not listed.
- **`idrefEdges[]` and `duplicateIds[]`.** One edge per IDREF token (the rows of `idrefs`, in order) with both ends, `dangling`, `duplicate`, the number of elements holding the id and `selfReference`; and every id that two or more elements hold, with their ids and lines.
- **`parseErrors[]`.** What set `malformed`: `stray-end-tag`, `misnested-end-tag`, `unclosed-raw-text` and `unclosed-at-end`, each with a line, the tag and the elements left open. Also on `PageIndex` from `parseHtml`.
- **`elements[].lang` and `elements[].langFrom`.** The language in force on the element (the nearest `lang`, trimmed; `""` is declared unknown and inherited; null is never declared) and the element that states it.
- **`stylesheets[]`.** `cssRules` grouped by the sheet they came from, in the same order, with the `<link>` or `<style>` line, its `media` attribute, its `href`, and a linked sheet the root does not hold (`resolved: false`, no rules).
- Types `CssDeclarationObs`, `ElementCssObs`, `StylesheetObs`, `ParseError`, `RouteIndexObservation`, `RouteIndexParams`, `RoutePage`, `NavigationRow`, `IdentificationRow`.

### Changed
- `SCHEMA_VERSION` is `"0.2"` and `DRIVER.version` `"0.2.0"`; `capabilities()` lists `route-index`.

## [0.1.0] — 2026-10-12

### Added
- `runHtmlIndex`: one observation per HTML page — elements with roles, accessible names, labels, hidden-ness and focusability; the IDREF graph; media; `lang`; the viewport meta; CSS rules; nested frame documents and declarative shadow trees; text blocks.
- `runFileIndex`: every file of a tree with its sha256 and size, text by path pattern, and pattern matches.
- `schemaVersion` `"0.1"` on every result.
- ARIA and ARIA-in-HTML tables are inputs; none is bundled.
- The observation and input types (`PageObservation`, `ElementObs`, `CssRuleObs`, `FrameObs`, `TextObs`, `AriaViews`, `HtmlAriaViews`, `HtmlIndexParams`, `HNode`, `PageIndex`, `SiteIndex`) are exported from the entry point.
