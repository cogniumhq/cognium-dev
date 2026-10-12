# Changelog

All notable changes to `@cognium/html-index` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-12

### Added
- `runHtmlIndex`: one observation per HTML page — elements with roles, accessible names, labels, hidden-ness and focusability; the IDREF graph; media; `lang`; the viewport meta; CSS rules; nested frame documents and declarative shadow trees; text blocks.
- `runFileIndex`: every file of a tree with its sha256 and size, text by path pattern, and pattern matches.
- `schemaVersion` `"0.1"` on every result.
- ARIA and ARIA-in-HTML tables are inputs; none is bundled.
- The observation and input types (`PageObservation`, `ElementObs`, `CssRuleObs`, `FrameObs`, `TextObs`, `AriaViews`, `HtmlAriaViews`, `HtmlIndexParams`, `HNode`, `PageIndex`, `SiteIndex`) are exported from the entry point.
