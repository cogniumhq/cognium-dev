/**
 * Centralized Security Rule Definitions
 *
 * Single source of truth for vulnerability types, severity levels,
 * descriptions, and remediation advice used across the codebase.
 */

import type { SinkType, Severity } from '../types/index.js';

// =============================================================================
// Sink Categories
// =============================================================================

/** Sinks that warrant critical severity when exploitable. */
export const CRITICAL_SINKS: SinkType[] = [
  'sql_injection',
  'command_injection',
  'deserialization',
  'code_injection',
];

/** Sinks that warrant high severity. */
export const HIGH_SINKS: SinkType[] = [
  'xss',
  'path_traversal',
  'xxe',
  'ssrf',
  'ldap_injection',
  'xpath_injection',
];

/** Source types that represent direct HTTP user input. */
export const HIGH_SEVERITY_SOURCES = [
  'http_param',
  'http_body',
  'http_header',
];

// =============================================================================
// Rule Information
// =============================================================================

export interface RuleInfo {
  /** Human-readable vulnerability name */
  name: string;
  /** Brief description for summaries */
  shortDescription: string;
  /** Detailed description for reports */
  fullDescription: string;
  /** Remediation guidance */
  remediation: string;
  /** CVSS-like severity score (0-10 scale as string) */
  cvssScore: string;
  /** Severity level category */
  severityLevel: Severity;
  /** CWE identifier */
  cwe: string;
}

/**
 * Complete rule definitions for all supported vulnerability types.
 */
export const RULE_DEFINITIONS: Record<SinkType, RuleInfo> = {
  sql_injection: {
    name: 'SQL Injection',
    shortDescription: 'User input used in SQL query without sanitization',
    fullDescription: 'The application constructs SQL queries using user-controlled input without proper sanitization or parameterization, allowing attackers to manipulate database queries.',
    remediation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL strings.',
    cvssScore: '9.8',
    severityLevel: 'critical',
    cwe: 'CWE-89',
  },
  nosql_injection: {
    name: 'NoSQL Injection',
    shortDescription: 'User input used in NoSQL query without sanitization',
    fullDescription: 'The application constructs NoSQL queries using user-controlled input, allowing attackers to manipulate database queries in MongoDB, CouchDB, or similar databases.',
    remediation: 'Validate and sanitize user input. Use parameterized queries. Avoid using $where with user input.',
    cvssScore: '9.8',
    severityLevel: 'critical',
    cwe: 'CWE-943',
  },
  command_injection: {
    name: 'Command Injection',
    shortDescription: 'User input used in system command without sanitization',
    fullDescription: 'The application executes system commands using user-controlled input, allowing attackers to execute arbitrary commands on the server.',
    remediation: 'Avoid executing system commands with user input. If necessary, use strict input validation and avoid shell interpreters.',
    cvssScore: '9.8',
    severityLevel: 'critical',
    cwe: 'CWE-78',
  },
  xss: {
    name: 'Cross-Site Scripting (XSS)',
    shortDescription: 'User input rendered in HTML without encoding',
    fullDescription: 'The application includes user-controlled input in HTML output without proper encoding, allowing attackers to inject malicious scripts.',
    remediation: 'Encode all user input before rendering in HTML. Use context-appropriate encoding (HTML, JavaScript, URL, CSS).',
    cvssScore: '6.1',
    severityLevel: 'medium',
    cwe: 'CWE-79',
  },
  path_traversal: {
    name: 'Path Traversal',
    shortDescription: 'User input used in file path without validation',
    fullDescription: 'The application uses user-controlled input to construct file paths, allowing attackers to access files outside the intended directory.',
    remediation: 'Validate and sanitize file paths. Use allowlists for permitted directories. Resolve and verify canonical paths.',
    cvssScore: '7.5',
    severityLevel: 'high',
    cwe: 'CWE-22',
  },
  deserialization: {
    name: 'Unsafe Deserialization',
    shortDescription: 'Untrusted data deserialized without validation',
    fullDescription: 'The application deserializes data from untrusted sources, potentially allowing attackers to execute arbitrary code.',
    remediation: 'Avoid deserializing untrusted data. Use safe serialization formats like JSON. Implement integrity checks.',
    cvssScore: '9.8',
    severityLevel: 'critical',
    cwe: 'CWE-502',
  },
  xxe: {
    name: 'XML External Entity (XXE)',
    shortDescription: 'XML parser processes external entities from untrusted input',
    fullDescription: 'The application parses XML with external entity processing enabled, allowing attackers to read local files or make server-side requests.',
    remediation: 'Disable external entity processing in XML parsers. Use less complex data formats when possible.',
    cvssScore: '7.5',
    severityLevel: 'high',
    cwe: 'CWE-611',
  },
  ldap_injection: {
    name: 'LDAP Injection',
    shortDescription: 'User input used in LDAP query without sanitization',
    fullDescription: 'The application constructs LDAP queries using user-controlled input without proper sanitization.',
    remediation: 'Use parameterized LDAP queries. Escape special characters in user input.',
    cvssScore: '8.1',
    severityLevel: 'high',
    cwe: 'CWE-90',
  },
  xpath_injection: {
    name: 'XPath Injection',
    shortDescription: 'User input used in XPath query without sanitization',
    fullDescription: 'The application constructs XPath queries using user-controlled input without proper sanitization.',
    remediation: 'Use parameterized XPath queries. Compile expressions with variables instead of concatenation.',
    cvssScore: '7.5',
    severityLevel: 'high',
    cwe: 'CWE-643',
  },
  ssrf: {
    name: 'Server-Side Request Forgery (SSRF)',
    shortDescription: 'User input used in server-side URL request',
    fullDescription: 'The application makes HTTP requests to URLs controlled by user input, allowing attackers to access internal services.',
    remediation: 'Validate and allowlist URLs. Block private IP ranges and internal hostnames.',
    cvssScore: '8.6',
    severityLevel: 'high',
    cwe: 'CWE-918',
  },
  open_redirect: {
    name: 'Open Redirect',
    shortDescription: 'User input used in redirect URL',
    fullDescription: 'The application redirects to URLs controlled by user input, allowing attackers to redirect users to malicious sites.',
    remediation: 'Validate redirect URLs against an allowlist. Use relative URLs or validate the host component.',
    cvssScore: '6.1',
    severityLevel: 'medium',
    cwe: 'CWE-601',
  },
  log_injection: {
    name: 'Log Injection',
    shortDescription: 'User input written to logs without sanitization',
    fullDescription: 'The application writes user-controlled input directly to logs without sanitization, allowing attackers to forge log entries or inject malicious content.',
    remediation: 'Sanitize log messages by removing or escaping newlines and control characters.',
    cvssScore: '5.3',
    severityLevel: 'low',
    cwe: 'CWE-117',
  },
  code_injection: {
    name: 'Code Injection',
    shortDescription: 'User input executed as code',
    fullDescription: 'The application evaluates user-controlled input as code, allowing attackers to execute arbitrary code.',
    remediation: 'Avoid dynamic code evaluation. If necessary, use strict sandboxing and input validation.',
    cvssScore: '9.8',
    severityLevel: 'critical',
    cwe: 'CWE-94',
  },
  weak_random: {
    name: 'Weak Random Number Generator',
    shortDescription: 'Cryptographically weak random number generator used',
    fullDescription: 'The application uses a weak random number generator for security-sensitive operations.',
    remediation: 'Use java.security.SecureRandom instead of java.util.Random for security-sensitive operations.',
    cvssScore: '5.3',
    severityLevel: 'medium',
    cwe: 'CWE-330',
  },
  weak_hash: {
    name: 'Weak Hash Algorithm',
    shortDescription: 'Cryptographically weak hash algorithm used',
    fullDescription: 'The application uses a weak hash algorithm (MD5, SHA-1) for security-sensitive operations.',
    remediation: 'Use strong hash algorithms like SHA-256 or SHA-3. Avoid MD5 and SHA-1.',
    cvssScore: '5.3',
    severityLevel: 'medium',
    cwe: 'CWE-328',
  },
  weak_crypto: {
    name: 'Weak Cipher Algorithm',
    shortDescription: 'Cryptographically weak encryption algorithm used',
    fullDescription: 'The application uses a weak encryption algorithm that may be vulnerable to attacks.',
    remediation: 'Use strong encryption algorithms like AES. Avoid DES, 3DES, RC4, and Blowfish.',
    cvssScore: '5.3',
    severityLevel: 'medium',
    cwe: 'CWE-327',
  },
  insecure_cookie: {
    name: 'Insecure Cookie',
    shortDescription: 'Cookie set without security flags',
    fullDescription: 'The application sets cookies without Secure, HttpOnly, or SameSite flags.',
    remediation: 'Set Secure and HttpOnly flags on cookies. Use SameSite attribute.',
    cvssScore: '4.3',
    severityLevel: 'low',
    cwe: 'CWE-614',
  },
  trust_boundary: {
    name: 'Trust Boundary Violation',
    shortDescription: 'Untrusted data crosses trust boundary',
    fullDescription: 'The application stores untrusted user input in a trusted context (e.g., session).',
    remediation: 'Validate and sanitize data before storing in session. Do not trust user input.',
    cvssScore: '5.3',
    severityLevel: 'medium',
    cwe: 'CWE-501',
  },
  external_taint_escape: {
    name: 'Tainted Data Passed to External Method',
    shortDescription: 'User-controlled data passed to external method call',
    fullDescription: 'The application passes user-controlled data to an external method that cannot be analyzed. This may result in security vulnerabilities if the external method does not properly sanitize the data.',
    remediation: 'Sanitize user input before passing to external methods. Review external method documentation for security requirements.',
    cvssScore: '5.0',
    severityLevel: 'medium',
    cwe: 'CWE-668',
  },
};

// =============================================================================
// Lookup Functions
// =============================================================================

/**
 * Get complete rule information for a sink type.
 */
export function getRuleInfo(sinkType: SinkType | string): RuleInfo {
  const rule = RULE_DEFINITIONS[sinkType as SinkType];
  if (rule) {
    return rule;
  }

  // Fallback for unknown types
  return {
    name: sinkType,
    shortDescription: `Potential security issue: ${sinkType}`,
    fullDescription: `The application may be vulnerable to ${sinkType} attacks.`,
    remediation: 'Review and sanitize user input before use.',
    cvssScore: '5.0',
    severityLevel: 'medium',
    cwe: 'CWE-20',
  };
}

/**
 * Get remediation advice for a sink type.
 */
export function getRemediation(sinkType: SinkType | string): string {
  return getRuleInfo(sinkType).remediation;
}

/**
 * Get severity level for a sink type.
 */
export function getSeverityLevel(sinkType: SinkType | string): Severity {
  return getRuleInfo(sinkType).severityLevel;
}

/**
 * Get CWE identifier for a sink type.
 */
export function getCwe(sinkType: SinkType | string): string {
  return getRuleInfo(sinkType).cwe;
}

/**
 * Check if a sink type is critical severity.
 */
export function isCriticalSink(sinkType: SinkType | string): boolean {
  return CRITICAL_SINKS.includes(sinkType as SinkType);
}

/**
 * Check if a sink type is high severity.
 */
export function isHighSink(sinkType: SinkType | string): boolean {
  return HIGH_SINKS.includes(sinkType as SinkType);
}

// =============================================================================
// Source Descriptions
// =============================================================================

const SOURCE_DESCRIPTIONS: Record<string, string> = {
  http_param: 'User-controlled HTTP parameter',
  http_body: 'User-controlled request body',
  http_header: 'User-controlled HTTP header',
  http_cookie: 'User-controlled cookie value',
  http_path: 'User-controlled URL path',
  http_query: 'User-controlled query string',
  io_input: 'External file/console input',
  env_input: 'Environment variable',
  db_input: 'Database-sourced data',
  file_input: 'File content',
  network_input: 'Network input',
  config_param: 'Servlet configuration parameter',
};

/**
 * Get human-readable description for a source type.
 */
export function getSourceDescription(sourceType: string): string {
  return SOURCE_DESCRIPTIONS[sourceType] ?? 'Tainted data';
}

/**
 * Get human-readable description for a sink type.
 */
export function getSinkDescription(sinkType: SinkType | string): string {
  const rule = RULE_DEFINITIONS[sinkType as SinkType];
  if (rule) {
    // Convert name to lowercase description
    return rule.name.toLowerCase();
  }
  return 'dangerous operation';
}

// =============================================================================
// Severity Calculation
// =============================================================================

export interface SeverityContext {
  sourceType?: string;
  sinkType: SinkType | string;
  pathExists: boolean;
  confidence?: number;
}

/**
 * Calculate severity based on source, sink, and path information.
 */
export function calculateSeverity(context: SeverityContext): Severity {
  const { sourceType, sinkType, pathExists, confidence = 0.5 } = context;

  const isCritical = isCriticalSink(sinkType);
  const isHigh = isHighSink(sinkType);
  const isHttpSource = sourceType ? HIGH_SEVERITY_SOURCES.includes(sourceType) : false;

  // Critical: Direct path from HTTP to critical sink
  if (pathExists && isCritical && isHttpSource) {
    return 'critical';
  }

  // Critical: High confidence path to critical sink
  if (pathExists && isCritical && confidence > 0.8) {
    return 'critical';
  }

  // High: HTTP source to critical sink (even without confirmed path)
  if (isHttpSource && isCritical) {
    return 'high';
  }

  // High: Confirmed path to critical sink
  if (pathExists && isCritical) {
    return 'high';
  }

  // High: High confidence path to high-severity sink
  if (pathExists && isHigh && confidence > 0.8) {
    return 'high';
  }

  // Medium: Path exists but not critical
  if (pathExists) {
    return 'medium';
  }

  // Medium: Proximity to critical/high sink
  if (isCritical || isHigh) {
    return 'medium';
  }

  return 'low';
}
