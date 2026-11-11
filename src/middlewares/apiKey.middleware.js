import { env } from '../config/env.js';
import { timingSafeStringEqual } from '../core/utils/crypto.js';
import { AppError } from '../core/errors/AppError.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';

/**
 * API Gateway API Key Authentication Middleware
 * Used for service-to-service communication or partner client access.
 */
export function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return next(
      AppError.unauthorized(
        'Missing required X-API-Key header for gateway access',
        ErrorCodes.GATEWAY_KEY_MISSING
      )
    );
  }

  // Constant-time comparison to prevent side-channel timing analysis
  const isValid = timingSafeStringEqual(apiKey, env.GATEWAY_API_KEY);

  if (!isValid) {
    return next(
      AppError.unauthorized(
        'Invalid X-API-Key provided',
        ErrorCodes.GATEWAY_KEY_INVALID
      )
    );
  }

  // Mark request as authenticated via Gateway API Key
  req.isGatewayAuthenticated = true;
  next();
}
