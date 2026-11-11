import hpp from 'hpp';
import { AppError } from '../core/errors/AppError.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';
import { logger } from '../config/logger.js';

/**
 * Recursively inspects and sanitizes objects to eliminate MongoDB query operators ($) and dotted keys (.)
 *
 * @param {any} target - Target object/array/value to sanitize
 * @param {boolean} throwOnError - If true, throws AppError when an attack payload is identified
 * @returns {any} Sanitized output
 */
export function sanitizeNoSqlPayload(target, throwOnError = false) {
  if (target === null || typeof target !== 'object') {
    return target;
  }

  if (Array.isArray(target)) {
    return target.map((item) => sanitizeNoSqlPayload(item, throwOnError));
  }

  const cleanObject = {};

  for (const [key, value] of Object.entries(target)) {
    // Check if key attempts to inject MongoDB operators or navigate path properties
    if (key.startsWith('$') || key.includes('.')) {
      if (throwOnError) {
        throw new AppError(
          `Security violation: Forbidden NoSQL operator detected in key '${key}'`,
          400,
          ErrorCodes.NOSQL_INJECTION_DETECTED
        );
      }
      // Silently strip malicious keys in defense-in-depth mode
      continue;
    }

    cleanObject[key] = sanitizeNoSqlPayload(value, throwOnError);
  }

  return cleanObject;
}

/**
 * Deep NoSQL Injection Prevention Middleware
 * Sanitizes req.body, req.query, and req.params
 */
export function noSqlSanitizerMiddleware(req, res, next) {
  try {
    if (req.body && typeof req.body === 'object') {
      req.body = sanitizeNoSqlPayload(req.body, false);
    }

    if (req.query && typeof req.query === 'object') {
      req.query = sanitizeNoSqlPayload(req.query, false);
    }

    if (req.params && typeof req.params === 'object') {
      req.params = sanitizeNoSqlPayload(req.params, false);
    }

    next();
  } catch (error) {
    logger.warn('NoSQL Injection attempt neutralized', {
      ip: req.ip,
      path: req.originalUrl,
      error: error.message,
    });
    next(error);
  }
}

/**
 * HTTP Parameter Pollution (HPP) Middleware
 * Protects against array-manipulation attacks on query parameters
 */
export const hppProtection = hpp({
  whitelist: [
    'filter',
    'sort',
    'fields',
    'page',
    'limit',
  ],
});
