import { ErrorCodes } from './errorCodes.js';

/**
 * Base Application Security Operational Error
 * Operational errors represent anticipated failure modes (e.g., bad inputs, invalid credentials, rate limits).
 * Programmer errors (e.g., syntax errors, unhandled promise rejections) are flagged as isOperational = false.
 */
export class AppError extends Error {
  constructor(message, statusCode = 500, errorCode = ErrorCodes.INTERNAL_SERVER_ERROR, details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(message = 'Bad Request', errorCode = ErrorCodes.VALIDATION_ERROR, details = null) {
    return new AppError(message, 400, errorCode, details);
  }

  static unauthorized(message = 'Authentication required', errorCode = ErrorCodes.AUTH_TOKEN_MISSING) {
    return new AppError(message, 401, errorCode);
  }

  static forbidden(message = 'Access forbidden', errorCode = ErrorCodes.FORBIDDEN_INSUFFICIENT_PERMISSIONS) {
    return new AppError(message, 403, errorCode);
  }

  static notFound(message = 'Resource not found', errorCode = ErrorCodes.RESOURCE_NOT_FOUND) {
    return new AppError(message, 404, errorCode);
  }

  static conflict(message = 'Resource conflict', errorCode = ErrorCodes.RESOURCE_CONFLICT) {
    return new AppError(message, 409, errorCode);
  }

  static tooManyRequests(message = 'Rate limit exceeded', errorCode = ErrorCodes.RATE_LIMIT_EXCEEDED) {
    return new AppError(message, 429, errorCode);
  }

  static internal(message = 'An unexpected internal error occurred') {
    return new AppError(message, 500, ErrorCodes.INTERNAL_SERVER_ERROR);
  }
}
