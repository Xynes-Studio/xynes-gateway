/**
 * Safe JSON Parser
 *
 * SEC-BODYLIMIT-1: JSON parsing with depth/size guards to prevent JSON bomb attacks.
 * Returns generic error messages to avoid leaking internal details.
 */

/**
 * Limits for JSON parsing to prevent DoS attacks.
 */
export const JSON_PARSE_LIMITS = {
  /** Maximum nesting depth for objects/arrays */
  MAX_DEPTH: 32,
  /** Maximum length of object keys */
  MAX_KEY_LENGTH: 512,
  /** Maximum length of string values */
  MAX_STRING_LENGTH: 1_048_576, // 1 MB
  /** Maximum number of keys in an object */
  MAX_KEYS: 10_000,
  /** Maximum number of elements in an array */
  MAX_ARRAY_LENGTH: 100_000,
} as const;

/**
 * Error codes for JSON parsing failures.
 */
export type JsonParseErrorCode =
  | "INVALID_JSON"
  | "JSON_TOO_DEEP"
  | "KEY_TOO_LONG"
  | "STRING_TOO_LONG"
  | "TOO_MANY_KEYS"
  | "ARRAY_TOO_LONG";

/**
 * Custom error for JSON parsing failures.
 * Contains a safe, non-leaky message suitable for API responses.
 */
export class JsonParseError extends Error {
  readonly code: JsonParseErrorCode;

  constructor(code: JsonParseErrorCode, internalDetails?: string) {
    // Always use safe, generic messages for external consumption
    const safeMessage = getSafeMessage(code);
    super(safeMessage);
    this.name = "JsonParseError";
    this.code = code;

    // Log internal details for debugging (but don't expose to client)
    if (internalDetails && process.env.NODE_ENV !== "production") {
      console.debug(`[JsonParseError] ${code}: ${internalDetails}`);
    }
  }
}

/**
 * Get a safe, non-leaky error message for the given code.
 */
function getSafeMessage(code: JsonParseErrorCode): string {
  switch (code) {
    case "INVALID_JSON":
      return "Invalid JSON payload";
    case "JSON_TOO_DEEP":
      return "Invalid JSON payload";
    case "KEY_TOO_LONG":
      return "Invalid JSON payload";
    case "STRING_TOO_LONG":
      return "Invalid JSON payload";
    case "TOO_MANY_KEYS":
      return "Invalid JSON payload";
    case "ARRAY_TOO_LONG":
      return "Invalid JSON payload";
    default:
      return "Invalid JSON payload";
  }
}

/**
 * Safely parse JSON with depth, size, and structure guards.
 *
 * @param text - The JSON string to parse
 * @param limits - Optional custom limits (defaults to JSON_PARSE_LIMITS)
 * @returns The parsed JSON value
 * @throws JsonParseError if parsing fails or limits are exceeded
 */
export function safeJsonParse(
  text: string,
  limits: Partial<typeof JSON_PARSE_LIMITS> = {}
): unknown {
  const effectiveLimits = { ...JSON_PARSE_LIMITS, ...limits };

  // Quick validation: empty or whitespace-only
  if (!text || text.trim().length === 0) {
    throw new JsonParseError("INVALID_JSON", "Empty input");
  }

  // First, do a basic JSON.parse to validate syntax
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new JsonParseError(
      "INVALID_JSON",
      e instanceof Error ? e.message : "Parse failed"
    );
  }

  // Now validate the parsed structure
  validateStructure(parsed, effectiveLimits, 0);

  return parsed;
}

/**
 * Recursively validate the parsed JSON structure.
 */
function validateStructure(
  value: unknown,
  limits: typeof JSON_PARSE_LIMITS,
  depth: number
): void {
  // Check depth
  if (depth > limits.MAX_DEPTH) {
    throw new JsonParseError(
      "JSON_TOO_DEEP",
      `Depth ${depth} exceeds max ${limits.MAX_DEPTH}`
    );
  }

  if (value === null || value === undefined) {
    return;
  }

  if (typeof value === "string") {
    if (value.length > limits.MAX_STRING_LENGTH) {
      throw new JsonParseError(
        "STRING_TOO_LONG",
        `String length ${value.length} exceeds max ${limits.MAX_STRING_LENGTH}`
      );
    }
    return;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return;
  }

  if (Array.isArray(value)) {
    if (value.length > limits.MAX_ARRAY_LENGTH) {
      throw new JsonParseError(
        "ARRAY_TOO_LONG",
        `Array length ${value.length} exceeds max ${limits.MAX_ARRAY_LENGTH}`
      );
    }
    for (const item of value) {
      validateStructure(item, limits, depth + 1);
    }
    return;
  }

  if (typeof value === "object") {
    const keys = Object.keys(value);

    if (keys.length > limits.MAX_KEYS) {
      throw new JsonParseError(
        "TOO_MANY_KEYS",
        `Object has ${keys.length} keys, exceeds max ${limits.MAX_KEYS}`
      );
    }

    for (const key of keys) {
      if (key.length > limits.MAX_KEY_LENGTH) {
        throw new JsonParseError(
          "KEY_TOO_LONG",
          `Key length ${key.length} exceeds max ${limits.MAX_KEY_LENGTH}`
        );
      }
      validateStructure(
        (value as Record<string, unknown>)[key],
        limits,
        depth + 1
      );
    }
  }
}
