# Stable-ids conformance set (TypeScript)

Thirty consecutive commit pairs from public TypeScript repositories, and a
harness that measures how well a provider's `ids@0.1` ids hold across them.
For every declaration of the earlier commit in a touched file, the set records
an expected label, **stable** or **changed**, worked out by the rule below.
The harness reports the precision and recall of "stable" against those labels.

Not part of any published package. The labels were sealed before any engine
ids were run against the pairs: `manifest.json` carries a digest of every pin
and every label file, and `verify` checks them.

## Commands

From the repo root, after `npm ci` and, for the default provider,
`npm run build:all`. The labeller uses the root `typescript` dev dependency,
pinned to 6.0.3, the version that sealed the labels (the workspaces build
with their own TypeScript); `manifest.json` records it, and
`verify --relabel` says so if another version re-derives them.

    node bench/stable-ids/run.mjs list                  # the pinned pairs
    node bench/stable-ids/run.mjs verify                # digests and label files (no network)

    export CORPUS_ROOT=/abs/path/outside/the/repo
    node bench/stable-ids/run.mjs fetch                 # fetch missing pairs
    node bench/stable-ids/run.mjs check                 # verify fetched pairs (read-only)
    node bench/stable-ids/run.mjs verify --relabel      # re-derive every label and compare
    node bench/stable-ids/run.mjs score                 # circle-ir's ids against the labels
    node bench/stable-ids/run.mjs score --nodes         # also: node ids under stable bodies
    node bench/stable-ids/run.mjs score --provider bench/stable-ids/providers/reference.mjs
    node bench/stable-ids/run.mjs score --json out.json --strict [pair-id...]

`fetch`, `check` and `score` exit 1 when a pair is missing or differs from its
pin, and `score` exits 1 when the provider fails on any file (the report then
measures the failure, not the ids); `score --strict` also exits 1 unless
precision and recall are both 100%.

## Pins, licences and the corpus

Each pair is pinned in `manifest.json` by repository URL and the two commit
SHAs (the later commit and its only parent), with every touched file's git
blob id on both sides. Only repositories whose root licence file is MIT,
Apache-2.0 or BSD are admitted; each pair records its SPDX id and the licence
file's path and blob id at the later commit. No file from these
repositories is committed here, and no function body or statement. The label
files do carry, for each labelled declaration, its file path, name, line
numbers and signature, and a signature is text from the repository: the
declaration's type parameters, parameter types and return type, or a field's
type, as written (about 91 KB of type text across the set).

`fetch` follows the convention of bench's other corpora: everything lands
under `$CORPUS_ROOT` (here `$CORPUS_ROOT/stable-ids/<pair-id>/{before,after}/`),
never inside the repo. Per repository it makes a shallow (depth 2), blob-less
clone of the pinned commits, checks each pinned blob id against the trees,
writes out only the touched files, and deletes the clone. `check` recomputes
each file's blob id, so it needs neither git nor the network.

## The labelling rule (`stable-labels@1`)

`label.mjs` is the rule's only implementation. It parses with the TypeScript
compiler, not with the engine's parser, and never calls the engine.

**Files.** The `.ts`, `.tsx`, `.mts` and `.cts` files (declaration files
included) the commit adds, deletes, modifies or moves, as `git diff-tree -M50%`
reports them, except paths under `dist/`, `build/`, `vendor/`,
`node_modules/`, `__snapshots__/` or `fixture(s)/` and `*.gen.ts` /
`*.generated.ts`. Untouched files are not labelled: their text is identical on
both sides.

**Declarations.** In each file: the file itself (kind `module`); functions
(declarations, overload signatures, and `const f = () => …` /
`function` expressions); classes, interfaces, type aliases and enums (kind
`type`; a `const C = class {…}` too); methods, constructors and accessors;
class properties, interface properties and other module-level variables
(kind `field`); namespaces and ambient modules (kind `module`). Nothing
inside a function body is a declaration here: nested functions and callbacks
belong to the body that contains them. Destructuring variables, index and call
signatures, static blocks, imports and statements stay in the enclosing body.

**Identity.** A declaration is the same on both sides when all of these agree:
the module (the file path without its extension), the names of the enclosing
declarations, the kind, the name, and the signature. The signature is the
type parameters, each parameter's written type (or `_`), `?` for an optional
or defaulted parameter, `...` for a rest parameter, and the written return
type; accessors add `get ` / `set `, static members `static `, optional
members `?`. Parameter names never take part. Fields use their written type.
Types are compared as tokens, with formatting removed (below). A moved file
therefore changes the identity of everything in it.

**Tokens.** Each declaration is read as a token sequence: comments and
whitespace never appear, and the declaration's own name is left out (so a
rename keeps the text). Inside a container (the file, a class, an interface, a
namespace), each member declaration is replaced by one placeholder carrying its
kind, name and signature, so editing a method's body is a change to the
method, not to its class; adding, removing or renaming a member, or changing
its signature, is a change to the container. A member's modifiers, decorators
and `export` keyword belong to the member. Two views are compared:

- *as written*: tokens exactly as spelled (JSX text with its whitespace
  collapsed);
- *without formatting*: also string literals by value (quote style), no
  statement semicolons, no trailing commas, no type-member separators, no
  parentheses around a single bare arrow parameter or around JSX.

The *inner part* is the body proper: a function's block or arrow body, a
variable's or property's initializer, a type alias's right-hand side, the
braces of an enum, class, interface or namespace, the whole file for a file.

**Labels.** For a declaration of the earlier commit:

| Case | Label |
|---|---|
| same identity, tokens equal as written | **stable** |
| same identity, inner part differs without formatting | **changed** (body) |
| no declaration with the same identity on the later side | **changed** (identity) |

An identity change also records a reason, for reading only: `signature` (same
name, other signature), `moved` (same declaration in another module),
`parent-changed` (its enclosing declaration was renamed), `renamed` (same
module and enclosing names, other name, identical text), else `removed`.

**Set aside.** Where the rule above does not settle a label, the declaration
gets a `judgement` reason instead of a label and is left out of the score:

| Reason | When |
|---|---|
| `formatting` | the two sides differ only in the formatting choices listed above |
| `header` | same identity and inner part, but modifiers, decorators, parameter defaults or parameter names differ |
| `member-order` | a container whose only difference is the order of its members |
| `member-header` | a container one of whose members is set aside as `header` or `signature-order` |
| `signature-order` | the only same-named declaration on the later side has the same signature tokens in another order (`A \| B` against `B \| A`) |
| `duplicate` | two declarations share one identity on either side (merged interfaces or namespaces, same-signature overloads) |
| `parse-error` | either version of the file has syntax errors |

**Edit kinds.** Each pair lists the kinds it exercises, derived from its
labels: `body`, `signature`, `rename`, `move`, `reorder` (matched members of
one container whose relative order changed), `format` (a stable declaration
whose comments or whitespace changed, or a `formatting` judgement), `add`,
`remove`.

## Scoring

A provider is an ES module exporting `derive(code, file)`, which returns
`{ decls: [{ id, body_id, name, kind, start_line, end_line, parent }] }` for
one file (`parent` is null for the file's own module declaration; a result
without a `decls` array, with a declaration lacking a string `id` and
`body_id` or integer lines, or without a root declaration is a provider
error), and
optionally `describe()` and `nodes(code, file, ids)` (node ids grouped by the
body id they are keyed under). `providers/circle-ir.mjs` wraps
`deriveStableIds` (and `analyze` + `assignNodeIds` for `--nodes`), loading
`$CIRCLE_IR` or this checkout's `packages/circle-ir/dist/index.js`. To measure
ids that are exposed some other way, copy it and change `derive`.

For each labelled declaration the harness finds the provider's declaration:
the file's root for the file; otherwise the innermost declaration with the
same name whose lines hold the label's name line; failing that, the innermost
one starting on the label's first line or name line (declarations the provider
flags `unstable:anonymous` only when it has no others). It then looks for the
same `id` among the later commit's declarations and predicts **stable** (same
`id` and `body_id`), **body** (same `id`, other `body_id`), **identity** (no
such `id`) or **none** (no provider declaration). A stable prediction is
correct only when the later declaration it found is the one the label pairs it
with.

The report prints, with numerators and denominators: the precision and recall
of stable; how often a changed body keeps its declaration id; how often a
changed identity gets a new id, and apart from that how often the provider has
no declaration for it at all; the declarations set aside, by reason; the
declarations the provider has none for (and how many of those, and of the
stable ones, sit in files the provider reported as only partly parsed); a
confusion table; with `--nodes`, among the correctly stable declarations whose
body the provider gave node ids for, how many kept every node id (bodies with
none on either side are counted apart and never as kept); and the
disagreements.

`providers/reference.mjs` implements the labelling rule itself as ids. It
scores 100% by construction and checks the harness and the labels, not an
engine.

## Sealing

`run.mjs seal <selection>` builds `manifest.json` and `labels/` from lines of
`id repository-url later-sha`. The 30 pairs were chosen from recent
single-parent commits of the listed repositories that touch 1 to 20 labelled
files, to cover every edit kind across several repositories and licences
(`list` shows each pair's kinds). Choosing used only the labels, never engine
output. Changing the labelling rule means a new rule version, a new seal and a
new digest; `verify --relabel` re-derives every label from the fetched corpus
and must reproduce the sealed files byte for byte (the manifest records the
TypeScript version that sealed them).
