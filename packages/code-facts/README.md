# @cognium/code-facts

Static facts about a code change between two versions of a tree, read with [circle-ir](../circle-ir). It reports observations only and never says whether a fix is adequate. Tables are inputs; this package ships none.

| Capability | Function | Observation per anchor |
|---|---|---|
| `path-set-diff` | `runPathSetDiff(root, {}, { cwe, language })` | One anchor per path key: every source-to-sink path of the CWE at each version, its state (`absent` · `sanitized` · `guarded` · `present`) and the change (`removed` · `sanitized` · `guarded` · `unchanged` · `added` · `other`). A `site` anchor holds the counts and, per version, the unresolved edges, unresolved cross-file calls, budget flags and `complete` |
| `remedy-class` | `runRemedyClass(root, { table }, { cwe, language, scope?, pathSet? })` | One anchor per sink of a path the change closed, and with `scope: 'all'` also per sink of a path it left open. Each holds the row of the `safe-construct-table@0.1` that the changed code matches (`multiple`, `unrecognized` or `abstained` otherwise), every matched row with its steps, and the table's digest. A `site` anchor holds the counts by match |
| `dependency-calls` | `runDependencyCalls(root, { jar? }, { artifact, language: 'java', jarPath?, mavenRepo? })` | For a dependency bump (E02): one anchor per call site into the Maven artifact (`call:<file>:<line>:<col>`), `covered` when a test reaches it over strong edges, else `uncovered`, with the tests. A `site` anchor holds the artifact, its packages and where they came from (`jar` with its digest, or `table`), the counts, `covered`, and the unattributed sites (external calls that cannot be ruled in or out) |

`dependency-calls` reads **one tree** (`root` is a directory: check out the version under test). The packages come from `views.jar`, `jarPath`, or the local Maven repository (`$MAVEN_REPO_LOCAL`, else `~/.m2/repository`) for a `group:artifact:version`; without a jar, circle-ir's fallback table for the demo dependencies; an artifact none of these resolves throws circle-ir's `UnknownArtifact`. The jar's digest is in every anchor's `inputDigest`.

For the other capabilities, `root` is a **pin pair**, `{ before, after }`: two directories the caller has checked out. The package reads the language's files under each one, skipping `node_modules`, `.git`, `target`, `build`, `dist` and similar, and never follows symbolic links. It analyses each version with circle-ir and derives branch facts (and `ids@0.1` stable ids for TypeScript and JavaScript) per file.

```ts
import { runPathSetDiff, runRemedyClass, SCHEMA_VERSION } from '@cognium/code-facts';
import { readFileSync } from 'node:fs';

const pair = { before: '/work/subject@base', after: '/work/subject@fix' };
const paths = await runPathSetDiff(pair, {}, { cwe: 89, language: 'java' });
const rows = await runRemedyClass(pair, { table: readFileSync('cwe-89.yaml') }, { cwe: 89, language: 'java', pathSet: paths });
```

Every result is `{ driver, schemaVersion: '0.1', capability, anchors: [{ anchor, observation, inputDigest }], environmentDigest }`:

- `inputDigest` hashes the bytes of the files the anchor read at both versions (and the table's digest for `remedy-class`).
- `environmentDigest` hashes the Node runtime, this package's version and circle-ir's version.
- A consumer pins `SCHEMA_VERSION` and refuses any other.
- If the reader refuses the table, `runRemedyClass` throws circle-ir's `TableRefused`, so no observation exists for a refused table.

The output is deterministic: no network and no model, so the same trees, table and versions give byte-identical output.

Languages: Java, JavaScript, TypeScript, Python.

Requires a circle-ir release that includes `pathSetDiff`, `remedyClassOf`, `deriveBranchFacts` and `remedyClassOf`'s `scope` option, which is the release after 4.17.0.
