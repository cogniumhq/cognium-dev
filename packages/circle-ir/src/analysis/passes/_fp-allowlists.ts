/**
 * False-positive allowlist predicates shared across passes.
 *
 * Used by:
 *   - scan-secrets-pass: #176 PEM-delimiter and #174 CLI-option-key
 *   - weak-crypto-pass / weak-password-hash-pass: #175 protocol-mandated
 *     legacy auth (NTLM / Kerberos / SMB1 / SASL CRAM-MD5 / HTTP Digest)
 *
 * Each predicate is a pure function (no IO, no mutable state) so it is
 * safe to import from any pass without coupling.
 */

// ---- #176 PEM delimiter body-adjacency ----------------------------------

const PEM_BODY_RE = /[A-Za-z0-9+/]{30,}/;

/**
 * Real embedded PEM keys always have base64-shape body lines (>=30 chars
 * of [A-Za-z0-9+/]) within a few lines of the BEGIN delimiter. Constants,
 * error messages, and parser `contains()` calls do not — they hold only
 * the delimiter substring with no key material adjacent.
 */
export function pemHasInlineBody(lines: string[], hitLineIdx: number): boolean {
  const end = Math.min(hitLineIdx + 5, lines.length);
  for (let l = hitLineIdx; l < end; l++) {
    if (PEM_BODY_RE.test(lines[l] ?? '')) return true;
  }
  return false;
}

// ---- #174 CLI option-key constant ---------------------------------------

/**
 * Kebab-case identifier (joptsimple / picocli / argparse4j / commons-cli
 * option names). At least one hyphen, no uppercase, no underscore, no
 * special characters other than hyphen. JVM identifiers cannot contain
 * hyphens, so a hyphen-bearing string value is by construction not a JVM
 * string secret in any meaningful sense — it is the flag name the user
 * types on the command line.
 */
const CLI_OPTION_KEY_RE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$/;

export function isCliOptionKeyValue(value: string): boolean {
  return value.length <= 48 && CLI_OPTION_KEY_RE.test(value);
}

// ---- #175 protocol-mandated crypto file ---------------------------------

/**
 * File-path segment indicating a legacy-auth protocol implementation.
 * Matches `/ntlm/`, `/kerberos/`, `/krb5/`, `/smb/`, `/smb1/`,
 * `/sasl/cram-md5/`, `/digest/` anywhere in the path.
 */
const PROTOCOL_MANDATED_PATH_RE =
  /(?:^|[\\/])(?:ntlm|kerberos|krb5|smb1?|sasl[\\/]cram-md5?|digest)(?:[\\/]|$)/i;

/**
 * Class names commonly used for protocol-mandated legacy auth. Catches
 * NtlmEngine / NtlmScheme / Krb5Helper / KerberosClient / SmbSigning /
 * CramMd5Authenticator / DigestScheme variants.
 */
const PROTOCOL_MANDATED_CLASS_RE =
  /\b(?:N[Tt][Ll][Mm](?:Scheme|Engine|AuthHandler|AuthScheme)|Krb5\w+|KerberosClient|Smb\w*Signing|CramMd5\w*|DigestScheme)\b/;

/**
 * Inline RFC / Microsoft spec citation indicating the author knows the
 * algorithm is protocol-mandated. Useful for non-canonical paths/classes
 * where the developer left a citation comment.
 */
const PROTOCOL_MANDATED_CITATION_RE =
  /\b(?:MS-NLMP|RFC\s*4757|RFC\s*3961|RFC\s*2617|RFC\s*2195|CRAM-MD5)\b/i;

/**
 * Returns true when the file is a protocol-mandated legacy-auth
 * implementation (NTLM / Kerberos / SMB1 / SASL CRAM-MD5 / HTTP Digest).
 * In such files, DES/RC4/MD4/MD5 are hardcoded by the protocol spec;
 * switching algorithms would break interop with conformant peers.
 */
export function isProtocolMandatedCryptoFile(file: string, code: string): boolean {
  if (PROTOCOL_MANDATED_PATH_RE.test(file)) return true;
  if (PROTOCOL_MANDATED_CLASS_RE.test(code)) return true;
  if (PROTOCOL_MANDATED_CITATION_RE.test(code)) return true;
  return false;
}
