import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';
import { ApiResponse } from '../core/utils/response.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';
import { logger } from '../config/logger.js';

/**
 * Global Rate Limiter
 * Baseline protection against volumetric DoS and automated endpoint scanning.
 */
export const globalRateLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_GLOBAL_WINDOW_MS,
  max: env.RATE_LIMIT_GLOBAL_MAX,
  standardHeaders: 'draft-7', // Draft-7 RateLimit-* headers
  legacyHeaders: false, // Disables X-RateLimit-* headers
  handler: (req, res, next, options) => {
    logger.warn('Global rate limit exceeded', {
      ip: req.ip,
      path: req.originalUrl,
      method: req.method,
      limit: options.max,
    });

    return ApiResponse.error(
      res,
      'Too many requests. Please slow down and try again later.',
      429,
      ErrorCodes.RATE_LIMIT_EXCEEDED,
      {
        retryAfterSeconds: Math.ceil(options.windowMs / 1000),
      }
    );
  },
});

/**
 * Strict Authentication Rate Limiter
 * Hardened protection against Credential Stuffing, Brute-Force Password Guessing, and Token Spraying.
 */
export const authRateLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_AUTH_WINDOW_MS, // e.g. 15 minutes
  max: env.RATE_LIMIT_AUTH_MAX, // e.g. 5 attempts per window
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skipSuccessfulRequests: false, // Count both failed and successful attempts to prevent token harvesting
  handler: (req, res, next, options) => {
    logger.warn('SECURITY ALERT: Authentication rate limit exceeded', {
      ip: req.ip,
      path: req.originalUrl,
      email: req.body?.email ? '[REDACTED_ATTEMPT]' : undefined,
      limit: options.max,
    });

    return ApiResponse.error(
      res,
      'Too many failed authentication attempts from this IP. Account access throttled for defense. Please try again later.',
      429,
      ErrorCodes.AUTH_RATE_LIMIT_EXCEEDED,
      {
        retryAfterSeconds: Math.ceil(options.windowMs / 1000),
      }
    );
  },
});

/**
 * Sensitive Action Rate Limiter (e.g. Password Reset, Token Refresh, Session Revocation)
 */
export const sensitiveActionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    logger.warn('Sensitive action rate limit exceeded', {
      ip: req.ip,
      path: req.originalUrl,
    });

    return ApiResponse.error(
      res,
      'Too many sensitive requests. Please wait before retrying.',
      429,
      ErrorCodes.RATE_LIMIT_EXCEEDED,
      {
        retryAfterSeconds: Math.ceil(options.windowMs / 1000),
      }
    );
  },
});
