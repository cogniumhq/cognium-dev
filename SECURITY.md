# Security Policy

cognium-dev is itself a security tool, so we take vulnerabilities in
this codebase seriously.

## Supported versions

Security fixes ship on the two most-recent minor versions of each
package. Older releases receive patches only for critical issues at
maintainer discretion.

| Package       | Supported                     |
|---------------|-------------------------------|
| `circle-ir`   | latest minor + previous minor |
| `cognium-dev` | latest minor + previous minor |

Current published versions: see
[circle-ir on npm](https://www.npmjs.com/package/circle-ir) and
[cognium-dev on npm](https://www.npmjs.com/package/cognium-dev).

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Please use GitHub's private vulnerability reporting channel:

- [Report a vulnerability](https://github.com/cogniumhq/cognium-dev/security/advisories/new)

Include:

- The affected package (`circle-ir` or `cognium-dev`) and version(s).
- A minimal reproducer — a code snippet, YAML config, or CLI invocation
  that demonstrates the issue.
- Impact assessment (what an attacker can achieve).
- Any suggested remediation, if you have one.

## What to expect

- **Acknowledgement:** within 48 hours (business days).
- **Triage + severity assessment:** within 5 business days of
  acknowledgement.
- **Fix + coordinated disclosure:** target 90 days from the initial
  report. We will collaborate on a disclosure timeline that fits the
  severity and complexity of the issue.
- **Credit:** we will credit you in the release notes and the
  published advisory unless you request otherwise.

## Scope

In scope:

- Vulnerabilities in `circle-ir` (the analysis library) that allow
  code execution, denial of service, or data exposure when analysing
  attacker-controlled source code.
- Vulnerabilities in the `cognium-dev` CLI (path traversal, arbitrary
  file read/write, command injection) triggered by attacker-controlled
  input paths, config files, or scan targets.
- Vulnerabilities in our npm-published tarballs (supply-chain,
  install-time hooks, etc.).

Out of scope:

- **False positives / false negatives in analysis output** — please
  file these as normal [issues](https://github.com/cogniumhq/cognium-dev/issues).
- Missing coverage for a specific CWE or framework — same, normal
  issues.
- Vulnerabilities in third-party dependencies where no path exists to
  exploit them through cognium-dev's API surface. Please report those
  to the upstream project.

## PGP / signed commits

We don't currently publish a PGP key for security correspondence. The
private-advisory channel above is authenticated by GitHub and is the
preferred path.
