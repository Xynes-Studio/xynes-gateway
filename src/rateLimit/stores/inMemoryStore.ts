/**
 * In-Memory Rate Limit Store
 *
 * SEC-RATELIMIT-1: Sliding window rate limiter implementation.
 * Designed for development and single-instance deployments.
 * For production with multiple instances, replace with Redis backend.
 *
 * Algorithm: Sliding Window Log
 * - Stores timestamps of recent requests
 * - Allows for accurate rate limiting without token leakage
 * - Memory-efficient with automatic cleanup
 */

import type {
  IRateLimitStore,
  RateLimitConfig,
  RateLimitResult,
} from "../types";

/**
 * Entry in the rate limit store.
 * Tracks request timestamps within the window.
 */
interface RateLimitEntry {
  timestamps: number[]; // Unix timestamps in milliseconds
  lastCleanup: number;
}

/**
 * Configuration for the in-memory store.
 */
export interface InMemoryStoreConfig {
  /** Interval for garbage collection in milliseconds. Default: 60000 (1 minute) */
  cleanupIntervalMs?: number;
  /** Maximum entries before triggering cleanup. Default: 10000 */
  maxEntries?: number;
}

/**
 * In-memory sliding window rate limit store.
 * Thread-safe for single-process Node.js/Bun environments.
 */
export class InMemoryRateLimitStore implements IRateLimitStore {
  private store: Map<string, RateLimitEntry> = new Map();
  private cleanupIntervalMs: number;
  private maxEntries: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: InMemoryStoreConfig = {}) {
    this.cleanupIntervalMs = config.cleanupIntervalMs ?? 60_000;
    this.maxEntries = config.maxEntries ?? 10_000;

    // Start periodic cleanup
    this.startCleanup();
  }

  /**
   * Check if a request is allowed and consume a token if so.
   */
  async checkAndConsume(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowMs = config.windowSec * 1000;
    const effectiveLimit = Math.floor(config.limitCount * config.burstFactor);

    let entry = this.store.get(key);

    if (!entry) {
      entry = { timestamps: [], lastCleanup: now };
      this.store.set(key, entry);
    }

    // Clean old timestamps outside the window
    const windowStart = now - windowMs;
    entry.timestamps = entry.timestamps.filter((ts) => ts > windowStart);
    entry.lastCleanup = now;

    const currentCount = entry.timestamps.length;
    const remaining = Math.max(0, effectiveLimit - currentCount);
    const resetAt = Math.ceil((now + windowMs) / 1000);

    if (currentCount >= effectiveLimit) {
      // Calculate retry-after based on oldest timestamp in window
      const oldestTimestamp = entry.timestamps[0] ?? now;
      const retryAfter = Math.ceil((oldestTimestamp + windowMs - now) / 1000);

      return {
        allowed: false,
        remaining: 0,
        resetAt,
        limit: effectiveLimit,
        retryAfter: Math.max(1, retryAfter),
      };
    }

    // Allow the request and record timestamp
    entry.timestamps.push(now);

    return {
      allowed: true,
      remaining: remaining - 1, // Subtract the one we just consumed
      resetAt,
      limit: effectiveLimit,
    };
  }

  /**
   * Get current rate limit status without consuming a token.
   */
  async peek(key: string, config: RateLimitConfig): Promise<RateLimitResult> {
    const now = Date.now();
    const windowMs = config.windowSec * 1000;
    const effectiveLimit = Math.floor(config.limitCount * config.burstFactor);

    const entry = this.store.get(key);

    if (!entry) {
      return {
        allowed: true,
        remaining: effectiveLimit,
        resetAt: Math.ceil((now + windowMs) / 1000),
        limit: effectiveLimit,
      };
    }

    // Count timestamps within window
    const windowStart = now - windowMs;
    const validTimestamps = entry.timestamps.filter((ts) => ts > windowStart);
    const currentCount = validTimestamps.length;
    const remaining = Math.max(0, effectiveLimit - currentCount);
    const resetAt = Math.ceil((now + windowMs) / 1000);

    if (currentCount >= effectiveLimit) {
      const oldestTimestamp = validTimestamps[0] ?? now;
      const retryAfter = Math.ceil((oldestTimestamp + windowMs - now) / 1000);

      return {
        allowed: false,
        remaining: 0,
        resetAt,
        limit: effectiveLimit,
        retryAfter: Math.max(1, retryAfter),
      };
    }

    return {
      allowed: true,
      remaining,
      resetAt,
      limit: effectiveLimit,
    };
  }

  /**
   * Clear rate limit state for a specific key.
   */
  async clear(key: string): Promise<void> {
    this.store.delete(key);
  }

  /**
   * Clear all rate limit state.
   */
  async clearAll(): Promise<void> {
    this.store.clear();
  }

  /**
   * Get the current number of tracked keys (for monitoring).
   */
  getKeyCount(): number {
    return this.store.size;
  }

  /**
   * Start periodic cleanup of expired entries.
   */
  private startCleanup(): void {
    if (this.cleanupTimer) return;

    this.cleanupTimer = setInterval(() => {
      this.performCleanup();
    }, this.cleanupIntervalMs);

    // Ensure cleanup timer doesn't prevent process exit
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Perform garbage collection of expired entries.
   */
  private performCleanup(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    // Find entries with no recent activity
    for (const [key, entry] of this.store) {
      // Remove entries with no timestamps or very old last cleanup
      if (
        entry.timestamps.length === 0 ||
        now - entry.lastCleanup > this.cleanupIntervalMs * 2
      ) {
        keysToDelete.push(key);
      }
    }

    // Delete expired entries
    for (const key of keysToDelete) {
      this.store.delete(key);
    }

    // Emergency cleanup if we have too many entries
    if (this.store.size > this.maxEntries) {
      const entriesToRemove =
        this.store.size - Math.floor(this.maxEntries * 0.8);
      const sortedEntries = Array.from(this.store.entries()).sort(
        (a, b) => a[1].lastCleanup - b[1].lastCleanup
      );

      for (let i = 0; i < entriesToRemove && i < sortedEntries.length; i++) {
        const entry = sortedEntries[i];
        if (entry) {
          this.store.delete(entry[0]);
        }
      }
    }
  }

  /**
   * Stop the cleanup timer (for graceful shutdown or testing).
   */
  dispose(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}
