/**
 * Centralized logging module with dependency injection.
 *
 * By default uses a simple console-based logger (zero dependencies).
 * Consumers can inject a custom logger (e.g. pino) via setLogger().
 *
 * Usage:
 *   import { logger } from './utils/logger.js';
 *   logger.info('Processing file', { file: 'test.java' });
 *   logger.error('Failed to parse', { error: err.message });
 *
 * Injecting a custom logger (e.g. pino):
 *   import pino from 'pino';
 *   import { setLogger } from 'circle-ir';
 *   setLogger(pino({ level: 'debug' }));
 *
 * Log Levels (in order of severity):
 *   - trace: Very detailed debugging
 *   - debug: Debugging information
 *   - info: General information (default)
 *   - warn: Warnings
 *   - error: Errors
 *   - fatal: Fatal errors
 *   - silent: No logging
 */

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal' | 'silent';

export interface LoggerConfig {
  level?: LogLevel;
  name?: string;
}

/**
 * Interface for injectable loggers.
 * Compatible with pino, console, and custom implementations.
 */
export interface LoggerInstance {
  trace(msg: string, obj?: Record<string, unknown>): void;
  debug(msg: string, obj?: Record<string, unknown>): void;
  info(msg: string, obj?: Record<string, unknown>): void;
  warn(msg: string, obj?: Record<string, unknown>): void;
  error(msg: string, obj?: Record<string, unknown>): void;
  fatal(msg: string, obj?: Record<string, unknown>): void;
}

const LOG_LEVELS: Record<LogLevel, number> = {
  trace: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  fatal: 5,
  silent: 6,
};

let currentLevel: LogLevel = 'info';
let customLogger: LoggerInstance | null = null;

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVELS[level] >= LOG_LEVELS[currentLevel];
}

/**
 * Configure the logger. Should be called early in application startup.
 */
export function configureLogger(config: Partial<LoggerConfig>): void {
  if (config.level) {
    currentLevel = config.level;
  }
}

/**
 * Inject a custom logger implementation (e.g. pino).
 * The custom logger receives all log calls regardless of level filtering —
 * it is expected to handle its own level filtering.
 */
export function setLogger(instance: LoggerInstance): void {
  customLogger = instance;
}

/**
 * Set the log level dynamically
 */
export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

/**
 * Get the current log level
 */
export function getLogLevel(): LogLevel {
  return currentLevel;
}

/**
 * The main logger instance.
 * Use this for all logging throughout the application.
 */
export const logger = {
  trace: (msg: string, obj?: Record<string, unknown>) => {
    if (customLogger) { customLogger.trace(msg, obj); return; }
    if (shouldLog('trace')) console.debug(obj ? `[TRACE] ${msg} ${JSON.stringify(obj)}` : `[TRACE] ${msg}`);
  },

  debug: (msg: string, obj?: Record<string, unknown>) => {
    if (customLogger) { customLogger.debug(msg, obj); return; }
    if (shouldLog('debug')) console.debug(obj ? `[DEBUG] ${msg} ${JSON.stringify(obj)}` : `[DEBUG] ${msg}`);
  },

  info: (msg: string, obj?: Record<string, unknown>) => {
    if (customLogger) { customLogger.info(msg, obj); return; }
    if (shouldLog('info')) console.log(obj ? `[INFO] ${msg} ${JSON.stringify(obj)}` : `[INFO] ${msg}`);
  },

  warn: (msg: string, obj?: Record<string, unknown>) => {
    if (customLogger) { customLogger.warn(msg, obj); return; }
    if (shouldLog('warn')) console.warn(obj ? `[WARN] ${msg} ${JSON.stringify(obj)}` : `[WARN] ${msg}`);
  },

  error: (msg: string, obj?: Record<string, unknown>) => {
    if (customLogger) { customLogger.error(msg, obj); return; }
    if (shouldLog('error')) console.error(obj ? `[ERROR] ${msg} ${JSON.stringify(obj)}` : `[ERROR] ${msg}`);
  },

  fatal: (msg: string, obj?: Record<string, unknown>) => {
    if (customLogger) { customLogger.fatal(msg, obj); return; }
    if (shouldLog('fatal')) console.error(obj ? `[FATAL] ${msg} ${JSON.stringify(obj)}` : `[FATAL] ${msg}`);
  },

  isLevelEnabled: (level: LogLevel): boolean => {
    return shouldLog(level);
  },
};
