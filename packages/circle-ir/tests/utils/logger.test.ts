/**
 * Tests for Logger Module
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  configureLogger,
  setLogLevel,
  getLogLevel,
  setLogger,
  logger,
  type LogLevel,
  type LoggerInstance,
} from '../../src/utils/logger.js';

describe('Logger', () => {
  beforeEach(() => {
    // Reset to defaults
    setLogger(null as unknown as LoggerInstance); // clear custom logger
    setLogLevel('info');
  });

  describe('configureLogger', () => {
    it('should configure log level', () => {
      configureLogger({ level: 'debug' });
      expect(getLogLevel()).toBe('debug');
    });

    it('should configure with name without throwing', () => {
      expect(() => configureLogger({ name: 'test-logger' })).not.toThrow();
    });

    it('should preserve level when configuring other options', () => {
      configureLogger({ level: 'warn' });
      configureLogger({ name: 'merged' });
      expect(getLogLevel()).toBe('warn');
    });
  });

  describe('setLogLevel', () => {
    it('should set trace level', () => {
      setLogLevel('trace');
      expect(getLogLevel()).toBe('trace');
    });

    it('should set debug level', () => {
      setLogLevel('debug');
      expect(getLogLevel()).toBe('debug');
    });

    it('should set info level', () => {
      setLogLevel('info');
      expect(getLogLevel()).toBe('info');
    });

    it('should set warn level', () => {
      setLogLevel('warn');
      expect(getLogLevel()).toBe('warn');
    });

    it('should set error level', () => {
      setLogLevel('error');
      expect(getLogLevel()).toBe('error');
    });

    it('should set fatal level', () => {
      setLogLevel('fatal');
      expect(getLogLevel()).toBe('fatal');
    });

    it('should set silent level', () => {
      setLogLevel('silent');
      expect(getLogLevel()).toBe('silent');
    });
  });

  describe('getLogLevel', () => {
    it('should return current log level', () => {
      setLogLevel('debug');
      expect(getLogLevel()).toBe('debug');
    });

    it('should default to info', () => {
      expect(getLogLevel()).toBe('info');
    });
  });

  describe('logger methods', () => {
    it('should have trace method', () => {
      expect(typeof logger.trace).toBe('function');
      expect(() => logger.trace('test trace')).not.toThrow();
    });

    it('should have debug method', () => {
      expect(typeof logger.debug).toBe('function');
      expect(() => logger.debug('test debug')).not.toThrow();
    });

    it('should have info method', () => {
      expect(typeof logger.info).toBe('function');
      expect(() => logger.info('test info')).not.toThrow();
    });

    it('should have warn method', () => {
      expect(typeof logger.warn).toBe('function');
      expect(() => logger.warn('test warn')).not.toThrow();
    });

    it('should have error method', () => {
      expect(typeof logger.error).toBe('function');
      expect(() => logger.error('test error')).not.toThrow();
    });

    it('should have fatal method', () => {
      expect(typeof logger.fatal).toBe('function');
      expect(() => logger.fatal('test fatal')).not.toThrow();
    });

    it('should have isLevelEnabled method', () => {
      expect(typeof logger.isLevelEnabled).toBe('function');
    });
  });

  describe('logger with object context', () => {
    it('should log info with object', () => {
      const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
      logger.info('info message', { key: 'value' });
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('info message'));
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('"key":"value"'));
      spy.mockRestore();
    });

    it('should log warn with object', () => {
      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      logger.warn('warn message', { key: 'value' });
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('warn message'));
      spy.mockRestore();
    });

    it('should log error with object', () => {
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      logger.error('error message', { error: 'test error' });
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('error message'));
      spy.mockRestore();
    });

    it('should log fatal with object', () => {
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      logger.fatal('fatal message', { error: 'test error' });
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('fatal message'));
      spy.mockRestore();
    });
  });

  describe('level filtering', () => {
    it('should not log below current level', () => {
      setLogLevel('warn');
      const debugSpy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      logger.debug('should not appear');
      logger.info('should not appear');
      expect(debugSpy).not.toHaveBeenCalled();
      expect(logSpy).not.toHaveBeenCalled();
      debugSpy.mockRestore();
      logSpy.mockRestore();
    });

    it('should log at and above current level', () => {
      setLogLevel('warn');
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      logger.warn('should appear');
      logger.error('should appear');
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(errorSpy).toHaveBeenCalledTimes(1);
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    });

    it('should log nothing at silent level', () => {
      setLogLevel('silent');
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      logger.fatal('should not appear');
      expect(errorSpy).not.toHaveBeenCalled();
      errorSpy.mockRestore();
    });
  });

  describe('isLevelEnabled', () => {
    it('should return true for enabled levels', () => {
      setLogLevel('info');
      expect(logger.isLevelEnabled('info')).toBe(true);
      expect(logger.isLevelEnabled('warn')).toBe(true);
      expect(logger.isLevelEnabled('error')).toBe(true);
    });

    it('should return false for disabled levels', () => {
      setLogLevel('error');
      expect(logger.isLevelEnabled('trace')).toBe(false);
      expect(logger.isLevelEnabled('debug')).toBe(false);
      expect(logger.isLevelEnabled('info')).toBe(false);
    });

    it('should handle silent level', () => {
      setLogLevel('silent');
      expect(logger.isLevelEnabled('fatal')).toBe(false);
    });
  });

  describe('setLogger (dependency injection)', () => {
    it('should delegate to custom logger when set', () => {
      const custom: LoggerInstance = {
        trace: vi.fn(),
        debug: vi.fn(),
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        fatal: vi.fn(),
      };
      setLogger(custom);

      logger.info('hello', { key: 'val' });
      logger.error('oops');
      logger.debug('dbg');

      expect(custom.info).toHaveBeenCalledWith('hello', { key: 'val' });
      expect(custom.error).toHaveBeenCalledWith('oops', undefined);
      expect(custom.debug).toHaveBeenCalledWith('dbg', undefined);
    });

    it('should bypass level filtering when custom logger is set', () => {
      const custom: LoggerInstance = {
        trace: vi.fn(),
        debug: vi.fn(),
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        fatal: vi.fn(),
      };
      setLogger(custom);
      setLogLevel('error'); // would normally filter debug

      logger.debug('should still reach custom logger');
      expect(custom.debug).toHaveBeenCalledWith('should still reach custom logger', undefined);
    });

    it('should revert to console when custom logger is cleared', () => {
      const custom: LoggerInstance = {
        trace: vi.fn(),
        debug: vi.fn(),
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        fatal: vi.fn(),
      };
      setLogger(custom);
      setLogger(null as unknown as LoggerInstance); // clear

      const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
      logger.info('back to console');
      expect(custom.info).not.toHaveBeenCalled();
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('back to console'));
      spy.mockRestore();
    });
  });
});
