import { AppError } from '../core/errors/AppError.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';

/**
 * Request Timeout Middleware
 * Enforces maximum execution duration for requests to prevent Slowloris and thread starvation.
 *
 * @param {number} timeoutMs - Timeout in milliseconds (default 30000ms = 30s)
 */
export function requestTimeout(timeoutMs = 30000) {
  return (req, res, next) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        next(
          new AppError(
            `Request timed out after ${timeoutMs / 1000} seconds`,
            504,
            ErrorCodes.REQUEST_TIMEOUT
          )
        );
      }
    }, timeoutMs);

    // Clear timer when response finishes or closes
    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));

    next();
  };
}
