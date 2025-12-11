/**
 * Request ID Generation Utility
 * Generates unique request IDs for tracing across logs and telemetry
 */

/**
 * Generates a unique request ID
 * Format: req_{timestamp}_{random}
 */
export function generateRequestId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `req_${timestamp}_${random}`;
}

/**
 * Validates if a string is a valid request ID format
 */
export function isValidRequestId(id: string): boolean {
  return /^req_[a-z0-9]+_[a-z0-9]+$/.test(id);
}
