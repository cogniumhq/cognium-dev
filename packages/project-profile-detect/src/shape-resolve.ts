/**
 * Shape resolver — maps module signals to a `ProjectShape` using the
 * signal-precedence order from ADR-008:
 *
 *   spring-boot > application/main() > java-library/exports
 *     > plugin > cli > unknown
 *
 * Hybrid policy (Approach C from ADR-008):
 *  - A module that is *both* application-shaped AND publicly published
 *    still resolves to its shape (`application`, `server`, `cli`) — the
 *    library downgrade applies only when the shape itself is `library`.
 *  - A module that is library-shaped (`java-library` plugin / JPMS
 *    exports / clear API-only structure) but NOT publicly published is
 *    downgraded to `application` — internal helper modules don't get the
 *    "library API surface" benefit-of-the-doubt.
 */

import type { BuildModule, ProjectShape } from './types.js';
import { isPubliclyPublished } from './publication-detect.js';

export interface ShapeResolution {
  shape: ProjectShape | 'unknown';
  reasons: string[];
}

export function resolveShape(mod: BuildModule): ShapeResolution {
  const sig = mod.signals;
  const has = (tag: string) => sig.plugins.includes(tag);
  const reasons: string[] = [];

  // 1. Spring Boot → application/server (strongest signal).
  if (has('spring-boot')) {
    reasons.push('spring-boot plugin');
    return { shape: 'server', reasons };
  }

  // 2. War / Ear packaging → server.
  if (has('war') || has('ear')) {
    reasons.push(has('war') ? 'war packaging' : 'ear packaging');
    return { shape: 'server', reasons };
  }

  // 3. Maven / Gradle plugin → plugin shape.
  if (has('maven-plugin') || has('gradle-plugin')) {
    reasons.push(has('maven-plugin') ? 'maven-plugin packaging' : 'gradle-plugin id');
    return { shape: 'plugin', reasons };
  }

  // 4. Application plugin or main() method → cli/application.
  //    Application plugin is the strongest CLI signal; raw main() alone
  //    is treated as `application` (the generic shape) since a main method
  //    can occur in a server / cli alike.
  if (has('application')) {
    reasons.push('application plugin');
    return { shape: 'cli', reasons };
  }
  if (sig.hasMainMethod) {
    reasons.push('main(String[]) found');
    return { shape: 'application', reasons };
  }

  // 5. Library shape signals.
  const libSignals: string[] = [];
  if (has('java-library')) libSignals.push('java-library plugin');
  if (sig.hasJpmsModuleInfo) libSignals.push('JPMS module-info.java');
  if (sig.hasSpiServices)    libSignals.push('META-INF/services SPI');

  if (libSignals.length > 0) {
    // Hybrid gate: only "real" libraries get the library shape.
    const published = isPubliclyPublished(sig.distributionUrls);
    if (published) {
      reasons.push(...libSignals, 'public-registry distribution');
      return { shape: 'library', reasons };
    }
    // Library-shaped but not publicly published → internal helper module.
    // Treat as application so it does NOT benefit from the library downgrade.
    reasons.push(...libSignals, 'no public-registry distribution (internal helper)');
    return { shape: 'application', reasons };
  }

  // 5b. Implicit library: publicly published with no application/server/plugin
  //     signals. Covers Maven libraries that don't carry an explicit
  //     `java-library` plugin / JPMS / SPI signal but inherit a public
  //     `<distributionManagement>` URL from a parent pom (e.g. langchain4j).
  //     The Hybrid Approach C public-registry allowlist still gates here.
  if (isPubliclyPublished(sig.distributionUrls)) {
    reasons.push('public-registry distribution',
                 'no application/server/plugin signals → implicit library');
    return { shape: 'library', reasons };
  }

  // 6. No usable signal → unknown (fail-safe).
  reasons.push('no shape signals');
  return { shape: 'unknown', reasons };
}
