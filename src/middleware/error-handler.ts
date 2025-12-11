
import type { Context } from 'hono';
import { DomainError } from '../types';
import { createErrorResponse } from '../types/envelope';
import { generateRequestId } from '../utils/requestId';

export const errorHandler = async (err: Error, c: Context) => {
  console.error(err);
  const requestId = c.get('requestId') || generateRequestId();

  if (err instanceof DomainError) {
    const errorResponse = createErrorResponse(err.code, err.message, requestId);
    return c.json(errorResponse, err.statusCode as 400 | 401 | 403 | 404 | 500);
  }

  const errorResponse = createErrorResponse('INTERNAL_SERVER_ERROR', 'An unexpected error occurred', requestId);
  return c.json(errorResponse, 500);
};

