/**
 * Tests for typed-overload deserialization sink classification.
 *
 * Jackson `ObjectMapper.readValue`, Gson `Gson.fromJson`, FastJson
 * `JSON.parseObject` (and the Yaml typed `load`/`loadAs` overloads) are unsafe
 * only when the deserialized type is not a compile-time class literal:
 *
 *   mapper.readValue(json)                       // UNSAFE — polymorphic
 *   mapper.readValue(json, User.class)           // SAFE  — fixed type
 *   mapper.readValue(json, Class.forName(t))     // UNSAFE — dynamic type
 *
 * Verifies the `safe_if_class_literal_at` SinkPattern field suppresses the
 * typed overload while leaving the untyped/dynamic forms as sinks.
 *
 * Closes cognium-dev#22.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';

async function deserializationSinksFor(code: string) {
  const tree = await parse(code, 'java');
  const calls = extractCalls(tree);
  const types = extractTypes(tree);
  const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');
  return taint.sinks.filter(s => s.type === 'deserialization');
}

describe('Typed-overload deserialization classification (#22)', () => {
  beforeAll(async () => {
    await initParser();
  });

  // ---------------------------------------------------------------------------
  // Jackson ObjectMapper.readValue
  // ---------------------------------------------------------------------------

  it('Jackson readValue(json, User.class) is NOT a deserialization sink', async () => {
    const code = `
public class Svc {
    public Object run(ObjectMapper mapper, String json) throws Exception {
        return mapper.readValue(json, User.class);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    expect(sinks.find(s => s.method === 'readValue')).toBeUndefined();
  });

  it('Jackson readValue(json) is a deserialization sink (1-arg untyped)', async () => {
    const code = `
public class Svc {
    public Object run(ObjectMapper mapper, String json) throws Exception {
        return mapper.readValue(json);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'readValue');
    expect(sink).toBeDefined();
    expect(sink!.cwe).toBe('CWE-502');
  });

  it('Jackson readValue(json, Class.forName(t)) is a deserialization sink (dynamic)', async () => {
    const code = `
public class Svc {
    public Object run(ObjectMapper mapper, String json, String t) throws Exception {
        return mapper.readValue(json, Class.forName(t));
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'readValue');
    expect(sink).toBeDefined();
    expect(sink!.cwe).toBe('CWE-502');
  });

  it('Jackson readValue(json, dto.getClass()) is a deserialization sink (dynamic via getClass)', async () => {
    const code = `
public class Svc {
    public Object run(ObjectMapper mapper, String json, Object dto) throws Exception {
        return mapper.readValue(json, dto.getClass());
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'readValue');
    expect(sink).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // Gson.fromJson
  // ---------------------------------------------------------------------------

  it('Gson fromJson(json, User.class) is NOT a deserialization sink', async () => {
    const code = `
public class Svc {
    public Object run(Gson gson, String json) {
        return gson.fromJson(json, User.class);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    expect(sinks.find(s => s.method === 'fromJson')).toBeUndefined();
  });

  it('Gson fromJson(json, type) is a deserialization sink (non-literal Type)', async () => {
    const code = `
public class Svc {
    public Object run(Gson gson, String json, java.lang.reflect.Type type) {
        return gson.fromJson(json, type);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'fromJson');
    expect(sink).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // FastJson JSON.parseObject
  // ---------------------------------------------------------------------------

  it('FastJson JSON.parseObject(json, User.class) is NOT a deserialization sink', async () => {
    const code = `
public class Svc {
    public Object run(String json) {
        return JSON.parseObject(json, User.class);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    expect(sinks.find(s => s.method === 'parseObject')).toBeUndefined();
  });

  it('FastJson JSON.parseObject(json) is a deserialization sink (1-arg untyped)', async () => {
    const code = `
public class Svc {
    public Object run(String json) {
        return JSON.parseObject(json);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'parseObject');
    expect(sink).toBeDefined();
  });

  it('FastJson JSON.parseObject(json, Class.forName(t)) is a deserialization sink', async () => {
    const code = `
public class Svc {
    public Object run(String json, String t) throws Exception {
        return JSON.parseObject(json, Class.forName(t));
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'parseObject');
    expect(sink).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // SnakeYAML Yaml.load / loadAs typed overloads
  // ---------------------------------------------------------------------------

  it('SnakeYAML yaml.load(stream, User.class) is NOT a deserialization sink', async () => {
    const code = `
public class Svc {
    public Object run(Yaml yaml, java.io.InputStream stream) {
        return yaml.load(stream, User.class);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    expect(sinks.find(s => s.method === 'load')).toBeUndefined();
  });

  it('SnakeYAML yaml.load(stream) is a deserialization sink (untyped)', async () => {
    const code = `
public class Svc {
    public Object run(Yaml yaml, java.io.InputStream stream) {
        return yaml.load(stream);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'load');
    expect(sink).toBeDefined();
  });

  it('SnakeYAML yaml.loadAs(stream, User.class) is NOT a deserialization sink', async () => {
    const code = `
public class Svc {
    public Object run(Yaml yaml, java.io.InputStream stream) {
        return yaml.loadAs(stream, User.class);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    expect(sinks.find(s => s.method === 'loadAs')).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // Class-literal regex shapes
  // ---------------------------------------------------------------------------

  it('fully-qualified class literal com.example.User.class is recognised as safe', async () => {
    const code = `
public class Svc {
    public Object run(ObjectMapper mapper, String json) throws Exception {
        return mapper.readValue(json, com.example.User.class);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    expect(sinks.find(s => s.method === 'readValue')).toBeUndefined();
  });

  it('array-class literal String[].class is recognised as safe', async () => {
    const code = `
public class Svc {
    public Object run(ObjectMapper mapper, String json) throws Exception {
        return mapper.readValue(json, String[].class);
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    expect(sinks.find(s => s.method === 'readValue')).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // Non-class-literal sinks (regression: gate must not over-suppress)
  // ---------------------------------------------------------------------------

  it('ObjectInputStream.readObject() is still a deserialization sink (no safe overload)', async () => {
    const code = `
public class Svc {
    public Object run(java.io.ObjectInputStream ois) throws Exception {
        return ois.readObject();
    }
}
`;
    const sinks = await deserializationSinksFor(code);
    const sink = sinks.find(s => s.method === 'readObject');
    expect(sink).toBeDefined();
    expect(sink!.cwe).toBe('CWE-502');
  });
});
