# Changelog

## [0.1.0] — unreleased

### Added
- First version. `capabilities()` returns `path-set-diff` and `remedy-class`.
- `runPathSetDiff(root, views, params)` and `runRemedyClass(root, views, params)` over a pin pair `{ before, after }`.
- `readTree()`, `DRIVER`, `SCHEMA_VERSION` `0.1`.
- Each version is analysed with circle-ir, with branch facts and (for TypeScript and JavaScript) stable ids derived per file. Results are keyed per path or per closed sink, with input digests over the files read and an environment digest.
