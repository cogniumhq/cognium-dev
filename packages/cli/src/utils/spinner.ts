/**
 * Lightweight spinner utility
 * Replaces ora dependency with zero-dependency alternative
 */

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const CHECKMARK = '✔';
const CROSS = '✖';
const WARNING = '⚠';

export class Spinner {
  private _text: string;
  private frameIndex = 0;
  private intervalId?: NodeJS.Timeout;
  private isSpinning = false;
  private enabled: boolean;

  constructor(text: string) {
    this._text = text;
    // Only animate when stderr is attached to an interactive terminal.
    // All spinner output is routed to stderr to keep stdout clean for piped
    // JSON/SARIF payloads. When stderr is piped, animation is disabled but
    // the final status line still emits (to stderr) so logs remain useful.
    this.enabled = Boolean(process.stderr.isTTY);
  }

  private render(frame: string): void {
    process.stderr.write(`\r\x1b[K${frame} ${this._text}`);
  }

  start(): this {
    if (this.isSpinning) return this;
    if (!this.enabled) return this;

    this.isSpinning = true;
    this.frameIndex = 0;

    // Hide cursor
    process.stderr.write('\x1b[?25l');

    // Render immediately so users see something even if the event loop is
    // briefly blocked by synchronous work right after start().
    this.render(SPINNER_FRAMES[this.frameIndex]);

    this.intervalId = setInterval(() => {
      // Advance frame after the initial render.
      this.frameIndex = (this.frameIndex + 1) % SPINNER_FRAMES.length;
      const frame = SPINNER_FRAMES[this.frameIndex];
      this.render(frame);
    }, 80);

    return this;
  }

  stop(): this {
    if (!this.isSpinning) return this;

    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }

    this.isSpinning = false;

    // Clear line and show cursor (stderr only — keeps stdout clean for pipes)
    process.stderr.write('\r\x1b[K');
    process.stderr.write('\x1b[?25h');

    return this;
  }

  succeed(text?: string): this {
    this.stop();
    const message = text || this._text;
    console.error(`\x1b[32m${CHECKMARK}\x1b[0m ${message}`);
    return this;
  }

  fail(text?: string): this {
    this.stop();
    const message = text || this._text;
    console.error(`\x1b[31m${CROSS}\x1b[0m ${message}`);
    return this;
  }

  warn(text?: string): this {
    this.stop();
    const message = text || this._text;
    console.error(`\x1b[33m${WARNING}\x1b[0m ${message}`);
    return this;
  }

  set text(value: string) {
    this._text = value;
    // Ensure progress messages are visible even when interval ticks are delayed
    // by CPU-heavy synchronous tasks.
    if (this.isSpinning && this.enabled) {
      this.render(SPINNER_FRAMES[this.frameIndex]);
    }
  }

  get text(): string {
    return this._text;
  }
}

export function spinner(text: string): Spinner {
  return new Spinner(text);
}
