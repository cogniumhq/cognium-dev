# Changelog

## [Unreleased]

## [0.1.0] - 2026-10-30

### Added
- `runRemedyClass(…, { outputContext: true })` passes circle-ir's opt-in output context through, and the `site` anchor records that it was asked for. Off by default.
- Java trees: server-side views (`.html`, `.htm`, `.jsp`, `.jspx`, `.tag`, `.tagx`) are read beside the code. Their template facts go to `path-set-diff` and `remedy-class`, so a fix made in a view is observed and matched against template rows. View files linked to a path count in its input digest. The HTML grammar is registered at init.
- First version. `capabilities()` returns `path-set-diff` and `remedy-class`.
- `runPathSetDiff(root, views, params)` and `runRemedyClass(root, views, params)` over a pin pair `{ before, after }`.
- `readTree()`, `DRIVER`, `SCHEMA_VERSION` `0.1`.
- Each version is analysed with circle-ir, with branch facts and (for TypeScript and JavaScript) stable ids derived per file. Results are keyed per path or per closed sink, with input digests over the files read and an environment digest.
