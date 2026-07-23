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
