/**
 * Lightweight ANSI color utilities
 * Replaces chalk dependency with zero-dependency alternative
 */

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

// Foreground colors (using bright variants for better visibility)
const RED = '\x1b[91m';      // Bright red
const GREEN = '\x1b[92m';    // Bright green
const YELLOW = '\x1b[93m';   // Bright yellow
const BLUE = '\x1b[94m';     // Bright blue
const CYAN = '\x1b[96m';     // Bright cyan
const MAGENTA = '\x1b[95m';  // Bright magenta

/**
 * Honor NO_COLOR (https://no-color.org/) and TERM=dumb.
 * Checked on each call so tests can toggle the env without re-importing.
 * Empty NO_COLOR does not disable color (spec: present and non-empty).
 */
export function colorEnabled(): boolean {
  const noColor = process.env.NO_COLOR;
  if (noColor !== undefined && noColor !== '') return false;
  if (process.env.TERM === 'dumb') return false;
  return true;
}

function paint(code: string, text: string): string {
  return colorEnabled() ? `${code}${text}${RESET}` : text;
}

export const colors = {
  red: (text: string) => paint(RED, text),
  green: (text: string) => paint(GREEN, text),
  yellow: (text: string) => paint(YELLOW, text),
  blue: (text: string) => paint(BLUE, text),
  cyan: (text: string) => paint(CYAN, text),
  magenta: (text: string) => paint(MAGENTA, text),
  bold: (text: string) => paint(BOLD, text),
  dim: (text: string) => text, // No dimming - keep text readable
};
