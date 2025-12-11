
import { describe, it, expect, vi } from 'vitest';
import { errorHandler } from './error-handler';
import { DomainError } from '../types';
import type { Context } from 'hono';

describe('errorHandler', () => {
    it('should transform DomainError into structured JSON response', async () => {
        const error = new DomainError('Invalid input', 'INVALID_INPUT', 400);
        
        const jsonMock = vi.fn();
        const c = {
            json: jsonMock,
        } as unknown as Context;

        await errorHandler(error, c);

        expect(jsonMock).toHaveBeenCalledWith({
            error: {
                code: 'INVALID_INPUT',
                message: 'Invalid input',
            },
        }, 400);
    });

    it('should handle generic errors as 500 INTERNAL_SERVER_ERROR', async () => {
        const error = new Error('Something went wrong');
        
        const jsonMock = vi.fn();
        const c = {
            json: jsonMock,
        } as unknown as Context;

        // Suppress console.error for this test
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

        await errorHandler(error, c);

        expect(jsonMock).toHaveBeenCalledWith({
            error: {
                code: 'INTERNAL_SERVER_ERROR',
                message: 'An unexpected error occurred',
            },
        }, 500);
        
        consoleSpy.mockRestore();
    });
});
