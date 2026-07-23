/**
 * Dependency-manifest helpers for the deserialization-safety-gate pass.
 *
 * cognium-dev #258 — dependency-version-aware sink gating. The engine
 * never reads the filesystem (Pillar I / browser-safety); the caller
 * (cognium-dev CLI or `analyzeProject`) reads the manifest and passes
 * it as raw text via `AnalyzerOptions.dependencyContext`. Helpers here
 * turn that raw text into the boolean predicates the gate needs.
 *
 * All parsers here are string-scoped: regex over the raw manifest
 * rather than a full XML/JSON tree. That is deliberate — the gate only
 * needs a handful of narrow signals (Fastjson version, presence of a
 * safe classifier), and every existing runtime dep in circle-ir is
 * either `web-tree-sitter` or `yaml`. Pulling in an XML parser purely
 * for one Fastjson property would violate the minimal-dependencies
 * guardrail.
 */

/**
 * Result of extracting the effective Fastjson coordinate from a
 * `pom.xml` string. `version` is the raw value as declared (including
 * any classifier suffix); `noneAutotype` is true when the version
 * literally matches Alibaba's `_noneautotype` hardened build family
 * (any patch level, e.g. `1.2.83_noneautotype`, `1.2.85_noneautotype`).
 */
export interface FastjsonPomResolution {
  version: string;
  noneAutotype: boolean;
}

/**
 * Extract the effective Fastjson version from a `pom.xml`. Two sources
 * are consulted:
 *
 *   1. A `<properties>` entry named exactly `<fastjson.version>` — the
 *      idiomatic way Maven projects centralise a dep version they
 *      reference in a `<dependencies>` block. This is where
 *      alibaba/Sentinel pins `1.2.83_noneautotype`.
 *   2. A `<dependency>` block whose `<groupId>` is `com.alibaba` and
 *      `<artifactId>` is `fastjson` — read as a fallback when the
 *      version is declared inline rather than as a property.
 *
 * Returns `null` when no Fastjson coordinate can be resolved from the
 * pom (no properties entry AND no matching dependency block, or the
 * dependency uses a `${...}` reference the properties block doesn't
 * define).
 */
export function resolveFastjsonFromPom(pomXml: string): FastjsonPomResolution | null {
  if (!pomXml) return null;

  const propMatch = pomXml.match(/<fastjson\.version>\s*([^<\s]+)\s*<\/fastjson\.version>/);
  if (propMatch) {
    const version = propMatch[1];
    return { version, noneAutotype: /_noneautotype/i.test(version) };
  }

  // Fallback: scan every <dependency>...</dependency> block for
  // com.alibaba:fastjson (or fastjson2). Non-greedy so we don't fuse
  // sibling blocks. Case-sensitive on artifact / group; Maven's own
  // resolution is case-sensitive too.
  const depRe = /<dependency>[\s\S]*?<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = depRe.exec(pomXml)) !== null) {
    const block = m[0];
    const gid = block.match(/<groupId>\s*([^<\s]+)\s*<\/groupId>/)?.[1];
    const aid = block.match(/<artifactId>\s*([^<\s]+)\s*<\/artifactId>/)?.[1];
    if (gid !== 'com.alibaba') continue;
    if (aid !== 'fastjson' && aid !== 'fastjson2') continue;
    const ver = block.match(/<version>\s*([^<\s]+)\s*<\/version>/)?.[1];
    if (!ver) continue;
    // `${fastjson.version}` reference the properties block did not
    // resolve — treat as unknown so the gate defaults to fire.
    if (/^\$\{/.test(ver)) return null;
    return { version: ver, noneAutotype: /_noneautotype/i.test(ver) };
  }

  return null;
}

/**
 * Extract the effective Fastjson version from a Gradle build script
 * (`build.gradle` Groovy DSL or `build.gradle.kts` Kotlin DSL).
 *
 * cognium-dev #261 (Gradle-first slice extending #258's pom.xml gate).
 *
 * Recognises three declaration shapes:
 *
 *   1. Direct literal — the classic Groovy / Kotlin single-string form:
 *        implementation 'com.alibaba:fastjson:1.2.83_noneautotype'
 *        implementation "com.alibaba:fastjson:1.2.83_noneautotype"
 *        implementation("com.alibaba:fastjson:1.2.83_noneautotype")
 *      Also `api`, `compile`, `runtimeOnly`, `testImplementation`, … — the
 *      configuration keyword is not part of the regex; only the
 *      `group:artifact:version` triple is matched, so any dependency-
 *      configuration prefix works.
 *
 *   2. Groovy interpolation — `implementation "com.alibaba:fastjson:${fastjsonVersion}"`
 *      with the property defined via `ext { fastjsonVersion = '1.2.83_noneautotype' }`,
 *      `def fastjsonVersion = '1.2.83_noneautotype'`, or top-level `fastjsonVersion = '…'`.
 *
 *   3. Kotlin interpolation — `implementation("com.alibaba:fastjson:$fastjsonVersion")`
 *      with the property defined via `val fastjsonVersion = "1.2.83_noneautotype"`
 *      or `const val fastjsonVersion = "…"`.
 *
 * Returns `null` on miss (no direct declaration AND no resolvable
 * property reference). The `DeserializationSafetyGatePass` then falls
 * through to its default "do not drop" behaviour on the sink.
 *
 * NOT recognised in this MVP (deferred, follow-ups on #261):
 *   - `platform(...)` / `enforcedPlatform(...)` BOM version imports
 *   - Version-catalog `libs.versions.toml` references (`libs.fastjson`)
 *   - `constraints { }` block versions
 *   - `subprojects { }` / `allprojects { }` conditional declarations
 */
export function resolveFastjsonFromGradle(buildGradle: string): FastjsonPomResolution | null {
  if (!buildGradle) return null;

  // Shape 1 — direct literal declaration. Accepts single-quoted,
  // double-quoted, or paren-wrapped ("Kotlin") forms. The version is
  // any non-quote / non-`$` / non-`)` / non-whitespace run.
  const directRe = /['"(]\s*com\.alibaba:fastjson:([^'"$\s)]+)\s*['")]/;
  const direct = buildGradle.match(directRe);
  if (direct) {
    const version = direct[1];
    return { version, noneAutotype: /_noneautotype/i.test(version) };
  }

  // Shapes 2 + 3 — property reference. Capture the property name (either
  // `${name}` Groovy form or `$name` bare form; Kotlin uses the same
  // string-template syntax as Groovy for this case).
  const propRefRe =
    /['"(]\s*com\.alibaba:fastjson:\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?\s*['")]/;
  const propRef = buildGradle.match(propRefRe);
  if (!propRef) return null;

  const propName = propRef[1];
  // Property definition — accept:
  //   `fastjsonVersion = 'X'`                (Groovy top-level or ext)
  //   `fastjsonVersion = "X"`                (Groovy interpolated)
  //   `def fastjsonVersion = 'X'`            (Groovy local)
  //   `val fastjsonVersion = "X"`            (Kotlin)
  //   `const val fastjsonVersion = "X"`      (Kotlin)
  //   `fastjsonVersion: 'X'`                 (Groovy map-syntax, rare)
  // Any leading whitespace / newlines / `=` / `:` before the quote.
  const defRe = new RegExp(
    `\\b${propName}\\s*[=:]\\s*['"]([^'"\\s]+)['"]`,
  );
  const def = buildGradle.match(defRe);
  if (!def) return null;

  const version = def[1];
  return { version, noneAutotype: /_noneautotype/i.test(version) };
}

/**
 * Extract the effective Fastjson version from a Gradle version-catalog
 * (`gradle/libs.versions.toml`) combined with the `build.gradle` script
 * that references it via a `libs.<alias>` accessor.
 *
 * cognium-dev #261 (Gradle catalog slice, extending the direct-Gradle
 * shape landed in the first Gradle slice).
 *
 * Recognises the two common `[libraries]` entry shapes:
 *
 *   fastjson = { module = "com.alibaba:fastjson", version.ref = "fastjson" }
 *   fastjson = { group = "com.alibaba", name = "fastjson", version.ref = "fastjson" }
 *
 * The version can be either a `version.ref` pointer into the
 * `[versions]` section, or an inline `version = "…"` on the library
 * entry itself. Both forms are handled.
 *
 * The build.gradle must reference the resolved alias via a
 * `libs.<alias>` accessor (or `libs.<dashed>` — Gradle normalises
 * dashes to dots for accessor names, but at the toml level the key
 * uses the original form; we match the toml alias here). If the alias
 * isn't referenced anywhere in the build.gradle, returns null — an
 * unreferenced catalog entry is not an active dependency.
 *
 * Returns null when no fastjson library entry exists, when the version
 * cannot be resolved, or when the alias is defined but unreferenced.
 * The `DeserializationSafetyGatePass` then falls through to its
 * default "do not drop" behaviour.
 */
export function resolveFastjsonFromGradleCatalog(
  buildGradle: string,
  libsVersionsToml: string,
): FastjsonPomResolution | null {
  if (!buildGradle || !libsVersionsToml) return null;

  // 1. Locate the [libraries] block. Non-greedy to next `[section]` or EOF.
  const librariesMatch = libsVersionsToml.match(
    /\[libraries\]([\s\S]*?)(?=\n\[|$)/,
  );
  if (!librariesMatch) return null;
  const librariesBlock = librariesMatch[1];

  // 2. Find the alias whose entry maps to com.alibaba:fastjson. Try
  //    both `module = "com.alibaba:fastjson"` and split
  //    `group = "com.alibaba"` + `name = "fastjson"` forms.
  const moduleForm = librariesBlock.match(
    /^\s*([\w.-]+)\s*=\s*\{[^}]*\bmodule\s*=\s*"com\.alibaba:fastjson"[^}]*\}/m,
  );
  const groupNameForm = librariesBlock.match(
    /^\s*([\w.-]+)\s*=\s*\{[^}]*\bgroup\s*=\s*"com\.alibaba"[^}]*\bname\s*=\s*"fastjson"[^}]*\}/m,
  );
  const entry = moduleForm ?? groupNameForm;
  if (!entry) return null;

  const alias = entry[1];
  const entryBody = entry[0];

  // 3. The build script must actually consume this alias — an unused
  //    catalog entry is not an active dep. The Gradle accessor form is
  //    `libs.<alias>` (or `libs.<pathified>` for dot-separated aliases;
  //    for the MVP we match the alias verbatim).
  const aliasEsc = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const aliasRefRe = new RegExp(`\\blibs\\s*\\.\\s*${aliasEsc}\\b`);
  if (!aliasRefRe.test(buildGradle)) return null;

  // 4. Extract version. Inline `version = "..."` on the library entry
  //    beats `version.ref` if both are present (matches Gradle's own
  //    resolution).
  const inlineVersionM = entryBody.match(
    /\bversion\s*=\s*"([^"$][^"]*)"/,
  );
  if (inlineVersionM) {
    const version = inlineVersionM[1];
    return { version, noneAutotype: /_noneautotype/i.test(version) };
  }

  const versionRefM = entryBody.match(/\bversion\.ref\s*=\s*"([^"]+)"/);
  if (!versionRefM) return null;

  const versionAlias = versionRefM[1];

  // 5. Look up the version-alias in the [versions] block.
  const versionsMatch = libsVersionsToml.match(
    /\[versions\]([\s\S]*?)(?=\n\[|$)/,
  );
  if (!versionsMatch) return null;
  const versionsBlock = versionsMatch[1];

  const versionAliasEsc = versionAlias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const versionLineRe = new RegExp(
    `^\\s*${versionAliasEsc}\\s*=\\s*"([^"]+)"`,
    'm',
  );
  const versionLine = versionsBlock.match(versionLineRe);
  if (!versionLine) return null;

  const version = versionLine[1];
  return { version, noneAutotype: /_noneautotype/i.test(version) };
}

// ---------------------------------------------------------------------------
// Python — PyYAML version detection (cognium-dev #261 Python slice)
// ---------------------------------------------------------------------------

/**
 * Result of extracting the effective PyYAML version. `safeByDefault` is
 * true when the parsed version is ≥ 6.0; at that point pyyaml.load()
 * without an explicit `Loader=` keyword argument raises TypeError
 * instead of silently invoking the unsafe default Loader.
 *
 * See https://github.com/yaml/pyyaml/blob/master/CHANGES for the full
 * 6.0 breakage story. The gate consumer must ALSO check the call site
 * for an explicit `Loader=` keyword (fileHasUnsafePyYamlLoader below)
 * — a caller under pyyaml ≥ 6.0 that explicitly passes
 * `Loader=yaml.Loader` or `Loader=yaml.UnsafeLoader` is still
 * dangerous regardless of the version pin.
 */
export interface PyYamlResolution {
  version: string;
  safeByDefault: boolean;
}

/**
 * Extract the effective PyYAML version from a `requirements.txt` file.
 * Recognises the standard PEP 508 shapes (`==`, `>=`, `~=`, `>`,
 * exact pins with trailing modifiers). Package name matched
 * case-insensitively (both `PyYAML` and `pyyaml` are common in the
 * wild).
 *
 * Returns null when no pyyaml line is found or the version string
 * cannot be parsed as `M.m[.p]`. Non-strict on trailing environment
 * markers (` ; python_version >= '3.6'`), which are common on
 * requirements.txt lines.
 */
export function resolvePyYamlFromRequirements(
  requirementsTxt: string,
): PyYamlResolution | null {
  if (!requirementsTxt) return null;

  // Iterate line-by-line so a fatal parse error on one line doesn't
  // sink the whole file. Comment lines and `-r other.txt` includes are
  // ignored (we don't recurse into included files here — the caller
  // controls what manifest string is passed).
  for (const rawLine of requirementsTxt.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    if (line.startsWith('-')) continue;

    // Match: `PyYAML==6.0`, `pyyaml>=6.0.1`, `PyYAML ~= 6.0`,
    // `pyyaml>6`, `PyYAML==6.0 ; python_version>='3.6'`
    const m = line.match(
      /^(pyyaml)\s*(==|>=|~=|>|===)\s*(\d+(?:\.\d+)*)/i,
    );
    if (!m) continue;
    const version = m[3];
    return { version, safeByDefault: isPyYamlVersionSafeByDefault(version) };
  }

  return null;
}

/**
 * Extract the effective PyYAML version from a `pyproject.toml`.
 * Recognises the common Poetry and PEP 621 shapes:
 *
 *   Poetry — under `[tool.poetry.dependencies]`:
 *     PyYAML = "6.0"
 *     pyyaml = "^6.0.1"
 *     pyyaml = { version = "6.0", extras = ["..."] }
 *
 *   PEP 621 — under `[project]` `dependencies` array:
 *     dependencies = [ "PyYAML>=6.0", ... ]
 *
 * As with the requirements.txt resolver, non-strict on markers /
 * modifiers; regex-based rather than a full TOML parser to keep the
 * runtime-dep list minimal (Pillar I minimal-dependencies principle).
 */
export function resolvePyYamlFromPyproject(
  pyprojectToml: string,
): PyYamlResolution | null {
  if (!pyprojectToml) return null;

  // Poetry key = string form.
  //   PyYAML = "6.0"     PyYAML = "^6.0"     pyyaml = "~=6.0"
  const poetryLine = pyprojectToml.match(
    /^\s*(pyyaml)\s*=\s*"([\^~=<>]*)(\d+(?:\.\d+)*)"/im,
  );
  if (poetryLine) {
    const version = poetryLine[3];
    return { version, safeByDefault: isPyYamlVersionSafeByDefault(version) };
  }

  // Poetry table form: `pyyaml = { version = "6.0", … }`
  const poetryTable = pyprojectToml.match(
    /^\s*(pyyaml)\s*=\s*\{[^}]*\bversion\s*=\s*"([\^~=<>]*)(\d+(?:\.\d+)*)"/im,
  );
  if (poetryTable) {
    const version = poetryTable[3];
    return { version, safeByDefault: isPyYamlVersionSafeByDefault(version) };
  }

  // PEP 621 array element: within a `dependencies = [ ... ]` block, a
  // string literal like `"PyYAML>=6.0"` or `"pyyaml==6.0.1"`.
  const pep621 = pyprojectToml.match(
    /"(pyyaml)\s*(==|>=|~=|>|===)\s*(\d+(?:\.\d+)*)/i,
  );
  if (pep621) {
    const version = pep621[3];
    return { version, safeByDefault: isPyYamlVersionSafeByDefault(version) };
  }

  return null;
}

/**
 * True when `version` (as `M.m[.p]`) is ≥ 6.0. Handles bare `6`,
 * `6.0`, `6.0.1`, `7`, `10.0`, etc. Returns false on malformed input
 * (defensive — the gate defaults to *do not drop* on missing signal).
 */
export function isPyYamlVersionSafeByDefault(version: string): boolean {
  const parts = version.split('.').map((s) => Number.parseInt(s, 10));
  if (parts.length === 0 || !Number.isFinite(parts[0])) return false;
  return parts[0] >= 6;
}

/**
 * Return true when the file contains an explicit unsafe `Loader=`
 * keyword argument on a `yaml.load(...)` call at or shortly after
 * `sinkLine`. Recognises the well-known unsafe loaders and their
 * qualified forms:
 *
 *   Loader=Loader         Loader=yaml.Loader
 *   Loader=UnsafeLoader   Loader=yaml.UnsafeLoader
 *   Loader=FullLoader     Loader=yaml.FullLoader   (technically safer
 *                                                   than Loader; still
 *                                                   permits arbitrary
 *                                                   Python object types)
 *
 * SafeLoader / CSafeLoader / BaseLoader / CBaseLoader are all safe and
 * are NOT matched here.
 *
 * Scans `sinkLine` through the next 9 lines to catch multi-line call
 * shapes; if the closing `)` appears before the window ends the scan
 * stops there. Regex-based (no AST inspection) to stay consistent with
 * the sink-filter-pass conventions and avoid pulling parse state into
 * the gate.
 */
export function fileHasUnsafePyYamlLoader(
  sourceLines: string[],
  sinkLine: number,
): boolean {
  const start = Math.max(0, sinkLine - 1);
  const end = Math.min(sourceLines.length, start + 10);
  const unsafeRe = /\bLoader\s*=\s*(?:yaml\s*\.\s*)?(?:Loader|UnsafeLoader|FullLoader)\b/;
  for (let i = start; i < end; i++) {
    const ln = sourceLines[i] ?? '';
    if (unsafeRe.test(ln)) return true;
    // Stop once the call closes — the `)` at the top-level. Fine
    // approximation: any bare `)` at the START of a stripped line, or
    // trailing `)` at end of a stripped line, signals close.
    const stripped = ln.trim();
    if (i > start && (stripped === ')' || stripped.endsWith(')'))) {
      // Also test the current line before we stop, in case Loader= is
      // on the same line as the closing paren.
      return false;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Rust — Cargo.toml dep resolution (cognium-dev #261 Rust slice, plumbing)
// ---------------------------------------------------------------------------

/**
 * Generic result: the declared version string + the parsed feature list
 * (for `[dependencies] pkg = { version = "…", features = ["safe"] }`
 * shapes). Returns null when the dep is absent, or when the version is
 * a `{ git = "…" }` / `{ path = "…" }` non-registry source (no version
 * string to compare against). Feature-set matching is left to the
 * caller; this helper only parses.
 */
export interface CargoDepResolution {
  version: string;
  features: string[];
}

/**
 * Extract the declared version + feature list for a named crate from a
 * `Cargo.toml`. Recognises the standard `[dependencies]` (and
 * `[dev-dependencies]` / `[build-dependencies]`) shapes:
 *
 *   pkg = "1.2.3"                              — bare string
 *   pkg = { version = "1.2.3" }                — table with version
 *   pkg = { version = "1.2.3", features = ["a", "b"] }
 *   pkg = { git = "…" }                        — git source (no version)
 *   pkg = { path = "…" }                       — path source (no version)
 *
 * Cross-table dependency declarations (`[dependencies.pkg]`) are not
 * yet recognised; those are less common and can be added when needed.
 * Regex-based rather than a full TOML parser to keep the runtime-dep
 * list minimal (Pillar I).
 */
export function resolveDepFromCargoToml(
  cargoToml: string,
  crateName: string,
): CargoDepResolution | null {
  if (!cargoToml || !crateName) return null;

  const nameEsc = crateName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Shape 1: bare string — `pkg = "1.2.3"`.
  const bareRe = new RegExp(
    `^\\s*${nameEsc}\\s*=\\s*"([\\d.]+[^"\\s]*)"`,
    'm',
  );
  const bare = cargoToml.match(bareRe);
  if (bare) {
    return { version: bare[1], features: [] };
  }

  // Shape 2: inline table — `pkg = { version = "1.2.3", features = [...] }`.
  // Match the table body then extract version + optional features.
  const tableRe = new RegExp(`^\\s*${nameEsc}\\s*=\\s*\\{([^}]*)\\}`, 'm');
  const table = cargoToml.match(tableRe);
  if (!table) return null;

  const body = table[1];
  const versionM = body.match(/\bversion\s*=\s*"([\d.]+[^"\s]*)"/);
  if (!versionM) return null;
  const version = versionM[1];

  const featuresM = body.match(/\bfeatures\s*=\s*\[([^\]]*)\]/);
  const features: string[] = [];
  if (featuresM) {
    const featureStr = featuresM[1];
    const re = /"([^"]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(featureStr)) !== null) {
      features.push(m[1]);
    }
  }

  return { version, features };
}

/**
 * Return true when the given source text contains an in-file call that
 * re-enables Fastjson autotype. Even a `_noneautotype` build does not
 * protect against code that programmatically re-enables the feature
 * (which the hardened build documents as impossible, but the classifier
 * is a build-time strip, not a runtime lock). Defense-in-depth for the
 * `resolveFastjsonFromPom` gate.
 */
export function fileReenablesFastjsonAutotype(source: string): boolean {
  if (!source) return false;
  // ParserConfig.getGlobalInstance().setAutoTypeSupport(true)
  // ParserConfig.setAutoTypeSupport(true)   (static-import form)
  return /\bsetAutoTypeSupport\s*\(\s*true\b/.test(source);
}

/**
 * Return true when the given Java source contains a call that enables
 * Jackson polymorphic type handling — either the legacy
 * `enableDefaultTyping(...)` (deprecated in Jackson 2.10+ but still
 * shipped) or the current `activateDefaultTyping(...)`.
 *
 * When neither is present in the file (and no `@JsonTypeInfo` is used
 * on the target type — best-effort scan below), Jackson's default
 * behaviour since 2.10 is safe: `ObjectMapper.readValue(json,
 * targetType)` cannot instantiate arbitrary classes. The gate uses
 * this to distinguish a genuine `readValue` sink from a safely-
 * configured one.
 *
 * `@JsonTypeInfo` scan is intentionally file-local. A `@JsonTypeInfo`
 * annotation on a target type in a different file would still allow
 * polymorphic construction, but the engine treats that as unknown
 * risk and preserves the sink (the gate only fires when the *file
 * itself* provides positive evidence of a safe configuration).
 */
export function fileEnablesJacksonPolymorphism(source: string): boolean {
  if (!source) return false;
  if (/\benableDefaultTyping\s*\(/.test(source)) return true;
  if (/\bactivateDefaultTyping\s*\(/.test(source)) return true;
  // @JsonTypeInfo(use = Id.CLASS) / (use = Id.MINIMAL_CLASS) / (use = Id.NAME)
  // enables polymorphic type handling on the annotated field or type.
  // The exact `use` argument doesn't matter for the gate — any
  // @JsonTypeInfo signals polymorphism is in play somewhere.
  if (/@JsonTypeInfo\b/.test(source)) return true;
  return false;
}

/**
 * Return true when the given Java source contains a
 * `new Yaml(new SafeConstructor(...))` or an equivalent hardened
 * SnakeYAML constructor. When any `Yaml` instance in the file is
 * built with the safe constructor family, we assume the file's
 * `Yaml.load(...)` calls are safely configured; the gate then drops
 * the deserialization sink for those calls.
 *
 * Recognised safe constructor classes (SnakeYAML 1.x + 2.x):
 *   - SafeConstructor              — canonical safe loader
 *   - SafeSchema (rare, YAML 1.2)  — safe schema-based loader
 *
 * Recognised safe factory calls (SnakeYAML 2.x LoaderOptions API):
 *   - Yaml.load()   with a Constructor that extends SafeConstructor
 *     (heuristic: any `SafeConstructor`-typed variable is safe)
 *
 * NOTE: A file that mixes `new Yaml(new SafeConstructor())` with
 * `new Yaml(new Constructor(SomeClass.class))` on separate call sites
 * would over-suppress the unsafe site. In practice this is rare (SAST
 * teams write one wrapper per file), and the current sink-filter
 * stage 9b handles the analogous compiled-template case with the same
 * file-scoped heuristic. If it becomes a problem, tighten to
 * receiver-scoped: check the specific `Yaml` receiver that carries
 * the load() call.
 */
export function fileConfiguresSnakeYamlSafely(source: string): boolean {
  if (!source) return false;
  if (/\bnew\s+SafeConstructor\s*\(/.test(source)) return true;
  // Explicit typed declaration form: `SafeConstructor sc = new SafeConstructor()`
  // or `SafeConstructor sc = ...` used in a Yaml constructor.
  if (/\bSafeConstructor\s+\w+\s*=/.test(source)) return true;
  return false;
}
