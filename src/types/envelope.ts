/**
 * Standard API Response Envelope Types
 * Provides consistent response structure across all gateway endpoints
 */

export interface ApiMeta {
  requestId: string;
}

export interface ApiSuccess<T> {
  ok: true;
  data: T;
  meta?: ApiMeta;
}

export interface ApiErrorPayload {
  code: string;
  message: string;
}

export interface ApiError {
  ok: false;
  error: ApiErrorPayload;
  meta?: ApiMeta;
}

export type ApiResponse<T> = ApiSuccess<T> | ApiError;

/**
 * Creates a successful API response
 */
export function createSuccessResponse<T>(data: T, requestId?: string): ApiSuccess<T> {
  const response: ApiSuccess<T> = {
    ok: true,
    data,
  };
  
  if (requestId) {
    response.meta = { requestId };
  }
  
  return response;
}

/**
 * Creates an error API response
 */
export function createErrorResponse(code: string, message: string, requestId?: string): ApiError {
  const response: ApiError = {
    ok: false,
    error: { code, message },
  };
  
  if (requestId) {
    response.meta = { requestId };
  }
  
  return response;
}
