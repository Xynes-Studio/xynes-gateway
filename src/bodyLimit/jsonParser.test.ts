/**
 * JSON Parser Tests
 *
 * SEC-BODYLIMIT-1: Unit tests for safe JSON parsing with depth/size guards.
 */

import { describe, it, expect } from "bun:test";
import { safeJsonParse, JsonParseError, JSON_PARSE_LIMITS } from "./jsonParser";

describe("JSON Parser", () => {
  describe("safeJsonParse", () => {
    it("should parse valid JSON", () => {
      const result = safeJsonParse('{"name": "test", "value": 123}');
      expect(result).toEqual({ name: "test", value: 123 });
    });

    it("should parse JSON arrays", () => {
      const result = safeJsonParse('[1, 2, 3, "four"]');
      expect(result).toEqual([1, 2, 3, "four"]);
    });

    it("should parse nested objects within depth limit", () => {
      const nested = { a: { b: { c: { d: 1 } } } }; // depth 4
      const result = safeJsonParse(JSON.stringify(nested));
      expect(result).toEqual(nested);
    });

    it("should throw JsonParseError for invalid JSON", () => {
      expect(() => safeJsonParse("not valid json")).toThrow(JsonParseError);
    });

    it("should throw JsonParseError with safe message for invalid JSON", () => {
      try {
        safeJsonParse("{invalid}");
        expect.unreachable("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(JsonParseError);
        const parseError = error as JsonParseError;
        expect(parseError.code).toBe("INVALID_JSON");
        expect(parseError.message).toBe("Invalid JSON payload");
        // Should NOT leak internal details
        expect(parseError.message).not.toContain("position");
        expect(parseError.message).not.toContain("Unexpected");
      }
    });

    it("should handle empty string", () => {
      expect(() => safeJsonParse("")).toThrow(JsonParseError);
    });

    it("should handle whitespace-only string", () => {
      expect(() => safeJsonParse("   ")).toThrow(JsonParseError);
    });

    it("should parse primitives", () => {
      expect(safeJsonParse("42")).toBe(42);
      expect(safeJsonParse('"hello"')).toBe("hello");
      expect(safeJsonParse("true")).toBe(true);
      expect(safeJsonParse("false")).toBe(false);
      expect(safeJsonParse("null")).toBe(null);
    });

    it("should handle unicode in strings", () => {
      const result = safeJsonParse('{"emoji": "🎉", "chinese": "中文"}');
      expect(result).toEqual({ emoji: "🎉", chinese: "中文" });
    });

    it("should handle escaped characters", () => {
      const result = safeJsonParse('{"path": "C:\\\\Users\\\\test"}');
      expect(result).toEqual({ path: "C:\\Users\\test" });
    });

    describe("depth limiting", () => {
      it("should reject deeply nested objects", () => {
        // Create JSON with depth exceeding limit
        const maxDepth = JSON_PARSE_LIMITS.MAX_DEPTH;
        let deepJson = '"value"';
        for (let i = 0; i <= maxDepth + 5; i++) {
          deepJson = `{"level${i}": ${deepJson}}`;
        }

        expect(() => safeJsonParse(deepJson)).toThrow(JsonParseError);
        try {
          safeJsonParse(deepJson);
        } catch (error) {
          expect((error as JsonParseError).code).toBe("JSON_TOO_DEEP");
        }
      });

      it("should reject deeply nested arrays", () => {
        const maxDepth = JSON_PARSE_LIMITS.MAX_DEPTH;
        let deepJson = "1";
        for (let i = 0; i <= maxDepth + 5; i++) {
          deepJson = `[${deepJson}]`;
        }

        expect(() => safeJsonParse(deepJson)).toThrow(JsonParseError);
      });

      it("should allow nesting up to the limit", () => {
        // Create JSON at exactly the limit
        const safeDepth = 15;
        let json = '"value"';
        for (let i = 0; i < safeDepth; i++) {
          json = `{"l${i}": ${json}}`;
        }

        expect(() => safeJsonParse(json)).not.toThrow();
      });
    });

    describe("size limiting", () => {
      it("should reject strings exceeding max key length", () => {
        const longKey = "a".repeat(JSON_PARSE_LIMITS.MAX_KEY_LENGTH + 100);
        const json = `{"${longKey}": "value"}`;

        expect(() => safeJsonParse(json)).toThrow(JsonParseError);
        try {
          safeJsonParse(json);
        } catch (error) {
          expect((error as JsonParseError).code).toBe("KEY_TOO_LONG");
        }
      });

      it("should reject strings exceeding max string length", () => {
        const longValue = "x".repeat(JSON_PARSE_LIMITS.MAX_STRING_LENGTH + 100);
        const json = `{"key": "${longValue}"}`;

        expect(() => safeJsonParse(json)).toThrow(JsonParseError);
        try {
          safeJsonParse(json);
        } catch (error) {
          expect((error as JsonParseError).code).toBe("STRING_TOO_LONG");
        }
      });

      it("should allow strings up to the limit", () => {
        const safeValue = "x".repeat(1000);
        const json = `{"key": "${safeValue}"}`;

        const result = safeJsonParse(json);
        expect((result as Record<string, string>).key).toBe(safeValue);
      });
    });

    describe("security edge cases", () => {
      it("should handle __proto__ key safely", () => {
        const json = '{"__proto__": {"polluted": true}}';
        const result = safeJsonParse(json);

        // Should parse but not pollute prototype
        expect(result).toBeDefined();
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();
      });

      it("should handle constructor key safely", () => {
        const json = '{"constructor": {"prototype": {}}}';
        const result = safeJsonParse(json);

        expect(result).toBeDefined();
        expect((result as Record<string, unknown>).constructor).toBeDefined();
      });

      it("should handle very large numbers", () => {
        const json = '{"big": 9999999999999999999999999999}';
        const result = safeJsonParse(json);

        // JavaScript will lose precision, but shouldn't crash
        expect(typeof (result as Record<string, unknown>).big).toBe("number");
      });

      it("should reject objects with too many keys", () => {
        const keys: string[] = [];
        for (let i = 0; i < JSON_PARSE_LIMITS.MAX_KEYS + 100; i++) {
          keys.push(`"key${i}": ${i}`);
        }
        const json = `{${keys.join(",")}}`;

        expect(() => safeJsonParse(json)).toThrow(JsonParseError);
        try {
          safeJsonParse(json);
        } catch (error) {
          expect((error as JsonParseError).code).toBe("TOO_MANY_KEYS");
        }
      });

      it("should reject arrays with too many elements", () => {
        const elements = Array(JSON_PARSE_LIMITS.MAX_ARRAY_LENGTH + 100)
          .fill(1)
          .join(",");
        const json = `[${elements}]`;

        expect(() => safeJsonParse(json)).toThrow(JsonParseError);
        try {
          safeJsonParse(json);
        } catch (error) {
          expect((error as JsonParseError).code).toBe("ARRAY_TOO_LONG");
        }
      });
    });
  });
});
