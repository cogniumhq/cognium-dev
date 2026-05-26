/**
 * Tests for Config Loader
 */

import { describe, it, expect } from 'vitest';
import {
  loadSourceConfigs,
  loadSinkConfigs,
  createTaintConfig,
  getDefaultConfig,
} from '../../src/analysis/config-loader.js';

describe('Config Loader', () => {
  describe('loadSourceConfigs', () => {
    it('should merge multiple source configs', () => {
      const configs = [
        {
          sources: [
            { method: 'getParam', class: 'Request', type: 'http_param', severity: 'high' as const, return_tainted: true },
          ],
        },
        {
          sources: [
            { method: 'getHeader', class: 'Request', type: 'http_header', severity: 'medium' as const, return_tainted: true },
          ],
        },
      ];

      const sources = loadSourceConfigs(configs);

      expect(sources).toHaveLength(2);
      expect(sources[0].method).toBe('getParam');
      expect(sources[1].method).toBe('getHeader');
    });

    it('should handle empty configs', () => {
      const sources = loadSourceConfigs([]);

      expect(sources).toHaveLength(0);
    });

    it('should handle config without sources', () => {
      const configs = [{}, { sources: [{ method: 'test', type: 'test', severity: 'low' as const, return_tainted: true }] }];

      const sources = loadSourceConfigs(configs);

      expect(sources).toHaveLength(1);
    });
  });

  describe('loadSinkConfigs', () => {
    it('should merge multiple sink configs', () => {
      const configs = [
        {
          sinks: [
            { method: 'executeQuery', class: 'Statement', type: 'sql_injection', severity: 'critical' as const, cwe: 89, tainted_args: [0] },
          ],
        },
        {
          sinks: [
            { method: 'exec', class: 'Runtime', type: 'command_injection', severity: 'critical' as const, cwe: 78, tainted_args: [0] },
          ],
        },
      ];

      const result = loadSinkConfigs(configs);

      expect(result.sinks).toHaveLength(2);
      expect(result.sinks[0].method).toBe('executeQuery');
      expect(result.sinks[1].method).toBe('exec');
    });

    it('should merge sanitizers from configs', () => {
      const configs = [
        {
          sanitizers: [
            { method: 'escapeHtml', return_sanitized: true },
          ],
        },
        {
          sanitizers: [
            { method: 'escapeSql', return_sanitized: true },
          ],
        },
      ];

      const result = loadSinkConfigs(configs);

      expect(result.sanitizers).toHaveLength(2);
    });

    it('should handle empty configs', () => {
      const result = loadSinkConfigs([]);

      expect(result.sinks).toHaveLength(0);
      expect(result.sanitizers).toHaveLength(0);
    });

    it('should handle config without sinks or sanitizers', () => {
      const configs = [
        {},
        { sinks: [{ method: 'test', type: 'test', severity: 'high' as const, cwe: 1, tainted_args: [0] }] },
      ];

      const result = loadSinkConfigs(configs);

      expect(result.sinks).toHaveLength(1);
      expect(result.sanitizers).toHaveLength(0);
    });
  });

  describe('createTaintConfig', () => {
    it('should create config from JSON strings', () => {
      const sourceContent = JSON.stringify({
        sources: [
          { method: 'getParameter', class: 'HttpServletRequest', type: 'http_param', severity: 'high', return_tainted: true },
        ],
      });
      const sinkContent = JSON.stringify({
        sinks: [
          { method: 'executeQuery', class: 'Statement', type: 'sql_injection', severity: 'critical', cwe: 89, tainted_args: [0] },
        ],
      });

      const config = createTaintConfig([sourceContent], [sinkContent]);

      expect(config.sources.length).toBeGreaterThan(0);
      expect(config.sinks.length).toBeGreaterThan(0);
    });

    it('should handle empty inputs', () => {
      const config = createTaintConfig([], []);

      expect(config.sources).toHaveLength(0);
      expect(config.sinks).toHaveLength(0);
      expect(config.sanitizers).toHaveLength(0);
    });

    it('should merge multiple source and sink configs', () => {
      const source1 = JSON.stringify({ sources: [{ method: 'm1', type: 't1', severity: 'high', return_tainted: true }] });
      const source2 = JSON.stringify({ sources: [{ method: 'm2', type: 't2', severity: 'high', return_tainted: true }] });
      const sink1 = JSON.stringify({ sinks: [{ method: 's1', type: 'sql_injection', severity: 'critical', cwe: 89, tainted_args: [0] }] });

      const config = createTaintConfig([source1, source2], [sink1]);

      expect(config.sources).toHaveLength(2);
      expect(config.sinks).toHaveLength(1);
    });
  });

  describe('getDefaultConfig', () => {
    it('should return valid default config', () => {
      const config = getDefaultConfig();

      expect(config.sources.length).toBeGreaterThan(0);
      expect(config.sinks.length).toBeGreaterThan(0);
    });

    it('should include HTTP parameter sources', () => {
      const config = getDefaultConfig();

      const httpParamSource = config.sources.find(s => s.method === 'getParameter');
      expect(httpParamSource).toBeDefined();
      expect(httpParamSource!.type).toBe('http_param');
    });

    it('should include SQL injection sinks', () => {
      const config = getDefaultConfig();

      const sqlSink = config.sinks.find(s => s.type === 'sql_injection');
      expect(sqlSink).toBeDefined();
    });

    it('should include command injection sinks', () => {
      const config = getDefaultConfig();

      const cmdSink = config.sinks.find(s => s.type === 'command_injection');
      expect(cmdSink).toBeDefined();
    });

    it('should include sanitizers', () => {
      const config = getDefaultConfig();

      expect(config.sanitizers).toBeDefined();
      expect(config.sanitizers!.length).toBeGreaterThan(0);
    });
  });
});
