# Known issues and accepted limitations

This page tracks accepted limitations and expected behaviour of cognium-dev. Items here are known and understood; they are recorded here instead of being kept as open issues. Each entry links to the issue that has the evidence. If you hit something that is not listed, please [open an issue](https://github.com/cogniumhq/cognium-dev/issues).

## Performance

| Limitation | Issue | Status |
|---|---|---|
| Project-profile detection walks large repositories several times, adding seconds to scans of very large monorepos. | [#304](https://github.com/cogniumhq/cognium-dev/issues/304) | Accepted; improvement welcome, not scheduled. |
| A few very large repositories (e.g. hapifhir `org.hl7.fhir.core`) take longer than 15 minutes to scan, so their CWE-Bench-Java CVEs count as misses under a timeout. Single-file analysis of the same code finds the expected flow. | [#616](https://github.com/cogniumhq/cognium-dev/issues/616) | Accepted; scan time on very large repos is a known limit. `--cross-file-budget-ms` bounds the cross-file phase. |

## Measurement

| Limitation | Issue | Status |
|---|---|---|
| C#/.NET is **Preview**. Single-file injection flows on NIST Juliet C# measure well, but cross-file C# taint (values carried through arrays, container fields, static fields, collections, or returned from another class) is not yet tracked, and C# sanitizer credit is not applied on cross-file paths. | [#599](https://github.com/cogniumhq/cognium-dev/issues/599) | Accepted for Preview; tracked as the C# measurement board. |
| EF Core injection coverage is **unverified**: there is no measured true positive for EF raw-SQL APIs yet, so EF Core is not claimed as a verified framework. | [#599](https://github.com/cogniumhq/cognium-dev/issues/599) | Accepted; docs no longer list EF Core as verified. |
| Juliet Java runs with the `require-entry-path` gate disabled, because the suite reaches `bad()` only through reflection. | [bench/README.md](../bench/README.md) | Expected; documented with the benchmark method. |

## Accepted detection losses

| Limitation | Issue | Status |
|---|---|---|
| Hibernate Validator CVE-2019-10219 (`@SafeHtml` bypass) is not detected. The bug is inside a sanitizer; taint analysis cannot detect a defective sanitizer by data flow, and the earlier hit was incidental. Counted in the "sanitizer-internal" class of CWE-Bench-Java. | [#617](https://github.com/cogniumhq/cognium-dev/issues/617) | Accepted; closed. |
