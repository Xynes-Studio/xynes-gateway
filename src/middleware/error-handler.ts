
import type { Context } from 'hono';
import { DomainError } from '../types';

export const errorHandler = async (err: Error, c: Context) => {
  console.error(err);

  if (err instanceof DomainError) {
    return c.json({
      error: {
        code: err.code,
        message: err.message,
      },
    }, err.statusCode as any);
  }

  return c.json({
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred',
    },
  }, 500);
};
