/**
 * Sprint 53 — cognium-dev #217: Java fluent-builder fixpoint hang.
 *
 * `analyze()` does not return for Java files using Keycloak-style fluent
 * builders with CYCLIC RETURN TYPES — `.property()` returns a sub-builder
 * (`ProviderConfigProperty`); `.add()` returns the outer builder
 * (`ProviderConfigurationBuilder`).
 *
 * Repro is the Keycloak `RoleStorageProviderSpi.java` (81 LOC, only 8
 * properties — so depth is NOT the trigger; cyclic return-type resolution
 * is). The fixpoint enters mutual recursion between two JIT-compiled
 * functions resolving the cyclic call chain.
 *
 * Suggested fix per ticket: iteration cap (~1000 rounds) or visited-set
 * guard inside the constant-propagation fixpoint loop. When the cap is
 * hit, conservatively mark affected values as `unknown`/`tainted` and
 * continue rather than looping.
 *
 * Locus: `isTaintedExpressionStep` in `constant-propagation/propagator.ts`
 * line ~2251 — on `method_invocation` nodes the step recurses into
 * `this.isTaintedExpression(objectNode)` (the receiver).
 *
 * Recall lock: the same chain with a tainted final argument must still
 * flow taint through to a downstream sink.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const KEYCLOAK_REPRO = `package org.keycloak.storage.role;

import java.util.Collections;
import java.util.List;

public class RoleStorageProviderSpi {
    public static final List<ProviderConfigProperty> commonConfig;

    static {
        List<ProviderConfigProperty> config = ProviderConfigurationBuilder.create()
            .property().name("enabled").type(ProviderConfigProperty.BOOLEAN_TYPE).add()
            .property().name("priority").type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name("cachePolicy").type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name("maxLifespan").type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name("evictionHour").type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name("evictionMinute").type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name("evictionDay").type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name("cacheInvalidBefore").type(ProviderConfigProperty.STRING_TYPE).add()
            .build();
        commonConfig = Collections.unmodifiableList(config);
    }
}

class ProviderConfigProperty {
    public static final String BOOLEAN_TYPE = "boolean";
    public static final String STRING_TYPE = "string";
}

class ProviderConfigurationBuilder {
    public static ProviderConfigPropertyBuilder create() { return new ProviderConfigPropertyBuilder(); }
}

class ProviderConfigPropertyBuilder {
    public ProviderConfigPropertyBuilder property() { return this; }
    public ProviderConfigPropertyBuilder name(String s) { return this; }
    public ProviderConfigPropertyBuilder type(String s) { return this; }
    public ProviderConfigPropertyBuilder add() { return this; }
    public java.util.List<ProviderConfigProperty> build() { return new java.util.ArrayList<>(); }
}
`;

describe('cognium-dev #217 — Java fluent-builder fixpoint hang', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('analyzes Keycloak-style cyclic fluent builder without hanging', async () => {
    const result = await analyze(KEYCLOAK_REPRO, 'RoleStorageProviderSpi.java', 'java');
    expect(result).toBeDefined();
    expect(result.parse_status?.success).toBe(true);
  }, 10000);

  it('recall — tainted concat sink at end of cyclic builder chain still fires', async () => {
    const code = `package com.example;
import org.springframework.web.bind.annotation.*;
import java.sql.*;

class CfgProperty {
    public CfgProperty name(String s) { return this; }
    public CfgProperty type(String s) { return this; }
    public CfgBuilder add() { return new CfgBuilder(); }
}

@RestController
public class CfgBuilder {
    public static CfgBuilder create() { return new CfgBuilder(); }
    public CfgProperty property() { return new CfgProperty(); }
    public void exec(Connection c, String sql) throws Exception {
        c.createStatement().executeQuery(sql);
    }
    @GetMapping("/q")
    public void run(@RequestParam String user, Connection c) throws Exception {
        CfgBuilder.create()
            .property().name("k1").type("string").add()
            .property().name("k2").type("string").add()
            .property().name("k3").type("string").add()
            .property().name("k4").type("string").add()
            .property().name("k5").type("string").add()
            .exec(c, "SELECT * FROM t WHERE u='" + user + "'");
    }
}
`;
    const result = await analyze(code, 'CfgBuilder.java', 'java');
    expect(result).toBeDefined();
    const sqlSinks = (result.taint?.sinks ?? []).filter(s => s.type === 'sql_injection');
    expect(sqlSinks.length).toBeGreaterThan(0);
  }, 10000);
});
