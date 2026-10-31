# Changelog

## [Unreleased]

## [0.1.0] - 2026-10-30

### Added
- First version. `capabilities()` returns `path-set-diff`, `remedy-class` and `dependency-calls`.
- Capability `dependency-calls` (E02): `runDependencyCalls(root, { jar? }, { artifact, language: 'java', jarPath?, mavenRepo? })` over one tree. One anchor per call into the Maven artifact, `covered` or `uncovered` with the tests that reach it, and a `site` anchor with the counts, the packages and their source (`jar` + digest, or `table`), and the unattributed sites — what the Loop's #89 evidence card lists. Finds the jar in the local Maven repository for a versioned coordinate. Needs circle-ir 4.18.0 (`dependencyCalls({ artifact })` and `unattributedSites`).
- `runRemedyClass(…, { outputContext: true })` passes circle-ir's opt-in output context through, and the `site` anchor records that it was asked for. Off by default.
- Java trees: server-side views (`.html`, `.htm`, `.jsp`, `.jspx`, `.tag`, `.tagx`) are read beside the code. Their template facts go to `path-set-diff` and `remedy-class`, so a fix made in a view is observed and matched against template rows. View files linked to a path count in its input digest. The HTML grammar is registered at init.
- `runPathSetDiff(root, views, params)` and `runRemedyClass(root, views, params)` over a pin pair `{ before, after }`.
- `readTree()`, `DRIVER`, `SCHEMA_VERSION` `0.1`.
- Each version is analysed with circle-ir, with branch facts and (for TypeScript and JavaScript) stable ids derived per file. Results are keyed per path or per closed sink, with input digests over the files read and an environment digest.
