# Changelog

All notable changes to `@cognium/html-index` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
