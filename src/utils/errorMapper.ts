/**
 * Error Code Mapping Utilities
 * Maps HTTP status codes to standardized error codes
 */

export enum ErrorCode {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  NOT_FOUND = 'NOT_FOUND',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  BAD_GATEWAY = 'BAD_GATEWAY',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

/**
 * Maps HTTP status codes to standard error codes
 */
export function mapStatusToErrorCode(status: number): ErrorCode {
  switch (status) {
    case 400:
      return ErrorCode.VALIDATION_ERROR;
    case 401:
      return ErrorCode.UNAUTHORIZED;
    case 403:
      return ErrorCode.FORBIDDEN;
    case 404:
      return ErrorCode.NOT_FOUND;
    case 500:
      return ErrorCode.INTERNAL_ERROR;
    case 502:
      return ErrorCode.BAD_GATEWAY;
    case 503:
      return ErrorCode.SERVICE_UNAVAILABLE;
    default:
      if (status >= 400 && status < 500) {
        return ErrorCode.VALIDATION_ERROR;
      }
      if (status >= 500) {
        return ErrorCode.INTERNAL_ERROR;
      }
      return ErrorCode.UNKNOWN_ERROR;
  }
}

/**
 * Gets a human-readable message for an error code
 */
export function getDefaultMessageForCode(code: ErrorCode): string {
  switch (code) {
    case ErrorCode.VALIDATION_ERROR:
      return 'Invalid request data';
    case ErrorCode.UNAUTHORIZED:
      return 'Authentication required';
    case ErrorCode.FORBIDDEN:
      return 'Access denied';
    case ErrorCode.NOT_FOUND:
      return 'Resource not found';
    case ErrorCode.INTERNAL_ERROR:
      return 'An unexpected error occurred';
    case ErrorCode.BAD_GATEWAY:
      return 'Upstream service unavailable';
    case ErrorCode.SERVICE_UNAVAILABLE:
      return 'Service temporarily unavailable';
    default:
      return 'An error occurred';
  }
}

/**
 * Extracts error details from a downstream response body
 */
export function extractErrorFromBody(body: unknown): { code: string; message: string } | null {
  if (typeof body === 'object' && body !== null) {
    const obj = body as Record<string, unknown>;
    
    // Check for standard error format
    if ('error' in obj && typeof obj.error === 'object' && obj.error !== null) {
      const error = obj.error as Record<string, unknown>;
      if (typeof error.code === 'string' && typeof error.message === 'string') {
        return { code: error.code, message: error.message };
      }
    }
    
    // Check for message at root level
    if (typeof obj.message === 'string') {
      const code = typeof obj.code === 'string' ? obj.code : 'ERROR';
      return { code, message: obj.message };
    }
  }
  
  return null;
}
