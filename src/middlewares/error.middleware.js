import { env } from '../config/env.js';
import { logger } from '../config/logger.js';
import { AppError } from '../core/errors/AppError.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';
import { ApiResponse } from '../core/utils/response.js';

/**
 * Hardened Central Error Handling Middleware
 * Guarantees zero sensitive data disclosure and consistent error contracts.
 */
export function errorHandlerMiddleware(err, req, res, next) {
  let error = err;

  // Handle malformed JSON body errors from express.json()
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    error = new AppError('Malformed JSON payload received in request body', 400, ErrorCodes.MALFORMED_PAYLOAD);
  }

  // Handle Mongoose duplicate key error (code 11000)
  if (err.name === 'MongoServerError' && err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'resource';
    error = new AppError(
      `A resource with this ${field} already exists.`,
      409,
      ErrorCodes.RESOURCE_CONFLICT,
      { field }
    );
  }

  // Handle Mongoose validation errors
  if (err.name === 'ValidationError') {
    const details = Object.values(err.errors || {}).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    error = new AppError('Database validation constraints failed', 400, ErrorCodes.VALIDATION_ERROR, details);
  }

  // Handle Mongoose invalid ObjectId / CastError
  if (err.name === 'CastError') {
    error = new AppError(`Invalid format for parameter '${err.path}'`, 400, ErrorCodes.VALIDATION_ERROR);
  }

  // Convert non-AppError exceptions to an operational AppError instance
  if (!(error instanceof AppError)) {
    const statusCode = error.statusCode || 500;
    const message = statusCode === 500 && env.NODE_ENV === 'production'
      ? 'An unexpected internal server error occurred.'
      : error.message || 'An error occurred';

    error = new AppError(message, statusCode, ErrorCodes.INTERNAL_SERVER_ERROR);
  }

  // Structured security logging of error
  logger.error('Request failed with error', {
    requestId: req.id,
    path: req.originalUrl,
    method: req.method,
    statusCode: error.statusCode,
    errorCode: error.errorCode,
    message: error.message,
    details: error.details,
    stack: env.NODE_ENV !== 'production' ? err.stack : undefined,
  });

  // Zero information leakage in production for 500 Internal Errors
  const safeMessage = (error.statusCode === 500 && env.NODE_ENV === 'production')
    ? 'An unexpected error occurred. Please contact support with the request ID.'
    : error.message;

  return ApiResponse.error(
    res,
    safeMessage,
    error.statusCode,
    error.errorCode,
    error.details,
    {
      requestId: req.id,
      stack: env.NODE_ENV === 'development' ? err.stack : undefined,
    }
  );
}

/**
 * 404 Route Not Found Middleware
 */
export function notFoundMiddleware(req, res, next) {
  next(
    new AppError(
      `Route '${req.method} ${req.originalUrl}' does not exist on this server.`,
      404,
      ErrorCodes.RESOURCE_NOT_FOUND
    )
  );
}
